import os
import traceback

import psycopg
from psycopg.rows import dict_row

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import (
    LoginManager, UserMixin, login_user, login_required, logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash


# =========================================================
# CONFIG
# =========================================================
APP_NAME = "Ipê"

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-ipe-secret-key-CHANGE-ME")

# Cookies melhores (produção/HTTPS)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# No Render (HTTPS), ative:
# app.config["SESSION_COOKIE_SECURE"] = True

# Cadastro aberto por padrão (convite opcional)
REQUIRE_INVITE = os.environ.get("IPE_REQUIRE_INVITE", "0").strip().lower() in ("1", "true", "yes")
INVITE_CODE = os.environ.get("IPE_INVITE_CODE", "IPE2026")

AREAS = ["Saúde", "Tecnologia", "Humanas", "Exatas", "Biológicas"]
EVIDENCIAS = ["Forte", "Moderada", "Inicial"]


# =========================================================
# POSTGRES (NEON)
# =========================================================
DATABASE_URL = (os.environ.get("DATABASE_URL") or "").strip()


def normalize_db_url(url: str) -> str:
    # alguns providers ainda retornam postgres://
    if url.startswith("postgres://"):
        return "postgresql://" + url[len("postgres://"):]
    return url


DATABASE_URL = normalize_db_url(DATABASE_URL)

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL não configurada. Defina a conexão do Neon no ambiente.")


def get_conn():
    # dict_row faz fetch retornar dict (compatível com seus templates)
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


def init_db():
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    email TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    nome TEXT NOT NULL,
                    instituicao TEXT,
                    created_at TIMESTAMP DEFAULT NOW()
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS pesquisas (
                    id SERIAL PRIMARY KEY,
                    pesquisador_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    pesquisador TEXT NOT NULL,
                    titulo TEXT NOT NULL,
                    area TEXT NOT NULL,
                    descoberta TEXT NOT NULL,
                    importancia TEXT,
                    aplicacao TEXT,
                    publico TEXT,
                    evidencia TEXT NOT NULL,
                    link_original TEXT NOT NULL,
                    imagem_url TEXT,
                    data_publicacao TIMESTAMP DEFAULT NOW()
                );
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_pesquisas_area ON pesquisas(area);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_pesquisas_pesquisador ON pesquisas(pesquisador);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_pesquisas_data ON pesquisas(data_publicacao);")
        conn.commit()


# Rode init_db no start (se falhar, melhor ver no log do Render)
init_db()


# =========================================================
# DEBUG 500 (Render logs)
# =========================================================
@app.errorhandler(500)
def internal_error(e):
    print("🔥 ERRO 500:", e)
    traceback.print_exc()
    return "Erro interno (500). Veja os logs do Render para detalhes.", 500


# =========================================================
# LOGIN
# =========================================================
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Por favor, faça login para publicar."
login_manager.login_message_category = "error"


class User(UserMixin):
    def __init__(self, id, email, nome, instituicao):
        self.id = id
        self.email = email
        self.nome = nome
        self.instituicao = instituicao


@login_manager.user_loader
def load_user(user_id):
    try:
        uid = int(user_id)
    except (TypeError, ValueError):
        return None

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, email, nome, instituicao FROM users WHERE id = %s",
                (uid,)
            )
            row = cur.fetchone()
            if row:
                return User(row["id"], row["email"], row["nome"], row.get("instituicao"))
    return None


# =========================================================
# AUTH ROUTES
# =========================================================
@app.route("/registro", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        nome = (request.form.get("nome") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        senha = (request.form.get("senha") or "").strip()
        senha2 = (request.form.get("senha2") or "").strip()
        instituicao = (request.form.get("instituicao") or "").strip()

        # Convite opcional
        if REQUIRE_INVITE:
            codigo = (request.form.get("codigo_convite") or "").strip()
            if codigo != INVITE_CODE:
                flash("Código de convite inválido.", "error")
                return render_template("register.html", app_name=APP_NAME, require_invite=REQUIRE_INVITE)

        # Validações
        if not nome or not email or not senha:
            flash("Preencha nome, email e senha.", "error")
            return render_template("register.html", app_name=APP_NAME, require_invite=REQUIRE_INVITE)

        if "@" not in email or "." not in email:
            flash("Email inválido.", "error")
            return render_template("register.html", app_name=APP_NAME, require_invite=REQUIRE_INVITE)

        if senha != senha2:
            flash("As senhas não coincidem.", "error")
            return render_template("register.html", app_name=APP_NAME, require_invite=REQUIRE_INVITE)

        if len(senha) < 6:
            flash("Senha muito curta. Use pelo menos 6 caracteres.", "error")
            return render_template("register.html", app_name=APP_NAME, require_invite=REQUIRE_INVITE)

        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id FROM users WHERE email = %s", (email,))
                if cur.fetchone():
                    flash("Este email já está cadastrado.", "error")
                    return render_template("register.html", app_name=APP_NAME, require_invite=REQUIRE_INVITE)

                hashed = generate_password_hash(senha)
                # ✅ CORRIGIDO: instituicao (sem typo)
                cur.execute(
                    "INSERT INTO users (email, password, nome, instituicao) VALUES (%s, %s, %s, %s)",
                    (email, hashed, nome, instituicao or None)
                )
            conn.commit()

        flash("Conta criada com sucesso! Faça login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html", app_name=APP_NAME, require_invite=REQUIRE_INVITE)


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        senha = (request.form.get("senha") or "").strip()

        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM users WHERE email = %s", (email,))
                row = cur.fetchone()

        if row and check_password_hash(row["password"], senha):
            user_obj = User(row["id"], row["email"], row["nome"], row.get("instituicao"))
            login_user(user_obj, remember=True)
            flash("Bem-vinda(o)!", "success")
            return redirect(url_for("index"))

        flash("Email ou senha incorretos.", "error")

    return render_template("login.html", app_name=APP_NAME)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Você saiu da conta.", "success")
    return redirect(url_for("index"))


# =========================================================
# APP ROUTES
# =========================================================
@app.route("/")
def index():
    filtro_area = (request.args.get("area") or "").strip()

    base_query = "SELECT * FROM pesquisas"
    params = ()

    if filtro_area and filtro_area in AREAS:
        query = base_query + " WHERE area = %s ORDER BY id DESC"
        params = (filtro_area,)
    else:
        query = base_query + " ORDER BY id DESC"

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(query, params)
            pesquisas = cur.fetchall()

    return render_template(
        "index.html",
        app_name=APP_NAME,
        pesquisas=pesquisas,
        areas=AREAS,
        filtro_area=filtro_area
    )


@app.route("/publicar", methods=["GET", "POST"])
@login_required
def publicar():
    if request.method == "POST":
        titulo = (request.form.get("titulo") or "").strip()
        area = (request.form.get("area") or "").strip()
        descoberta = (request.form.get("descoberta") or "").strip()
        link_original = (request.form.get("link_original") or "").strip()

        importancia = (request.form.get("importancia") or "").strip()
        aplicacao = (request.form.get("aplicacao") or "").strip()
        publico = (request.form.get("publico") or "").strip()
        evidencia = (request.form.get("evidencia") or "Inicial").strip()
        imagem_url = (request.form.get("imagem_url") or "").strip()

        if not titulo or not area or not descoberta or not link_original:
            flash("Preencha os campos obrigatórios.", "error")
            return render_template(
                "publicar.html",
                app_name=APP_NAME,
                areas=AREAS,
                evidencias=EVIDENCIAS,
                form=request.form
            )

        if area not in AREAS:
            area = "Humanas"
        if evidencia not in EVIDENCIAS:
            evidencia = "Inicial"

        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO pesquisas (
                        pesquisador_id, pesquisador, titulo, area, descoberta,
                        importancia, aplicacao, publico, evidencia, link_original, imagem_url
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """, (
                    int(current_user.id),
                    current_user.nome,
                    titulo,
                    area,
                    descoberta,
                    importancia or None,
                    aplicacao or None,
                    publico or None,
                    evidencia,
                    link_original,
                    imagem_url or None
                ))
            conn.commit()

        flash("Pesquisa publicada com sucesso!", "success")
        return redirect(url_for("index"))

    return render_template(
        "publicar.html",
        app_name=APP_NAME,
        areas=AREAS,
        evidencias=EVIDENCIAS,
        form={}
    )


@app.route("/perfil/<nome>")
def perfil(nome):
    nome = (nome or "").strip()

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM pesquisas WHERE pesquisador = %s ORDER BY id DESC",
                (nome,)
            )
            pesquisas = cur.fetchall()

    return render_template("perfil.html", app_name=APP_NAME, pesquisas=pesquisas, nome=nome)


@app.route("/sobre")
def sobre():
    return render_template(
        "sobre.html",
        app_name=APP_NAME,
        codigo_exemplo=(INVITE_CODE if REQUIRE_INVITE else "")
    )


# =========================================================
# RUN (LOCAL/RENDER)
# =========================================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    debug = os.environ.get("FLASK_DEBUG", "0").strip().lower() in ("1", "true", "yes")
    app.run(host="0.0.0.0", port=port, debug=debug)
