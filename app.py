import os

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

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# app.config["SESSION_COOKIE_SECURE"] = True  # ligar no Render (HTTPS)

REQUIRE_INVITE = os.environ.get("IPE_REQUIRE_INVITE", "0").strip().lower() in ("1", "true", "yes")
INVITE_CODE = os.environ.get("IPE_INVITE_CODE", "IPE2026")

AREAS = ["Saúde", "Tecnologia", "Humanas", "Exatas", "Biológicas"]
EVIDENCIAS = ["Forte", "Moderada", "Inicial"]


# =========================================================
# POSTGRES (NEON)
# =========================================================
DATABASE_URL = (os.environ.get("DATABASE_URL") or "").strip()


def normalize_db_url(url: str) -> str:
    if url.startswith("postgres://"):
        return "postgresql://" + url[len("postgres://"):]
    return url


DATABASE_URL = normalize_db_url(DATABASE_URL)
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL não configurada. Defina a conexão do Neon no ambiente (Render env).")


def get_conn():
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


def init_db():
    with get_conn() as conn:
        with conn.cursor() as cur:
            # users
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    email TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    nome TEXT NOT NULL,
                    instituicao TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # pesquisas
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
                    data_publicacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP,
                    views INTEGER NOT NULL DEFAULT 0
                );
            """)

            # migrações seguras
            cur.execute("ALTER TABLE pesquisas ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP;")
            cur.execute("ALTER TABLE pesquisas ADD COLUMN IF NOT EXISTS views INTEGER NOT NULL DEFAULT 0;")

            # likes
            cur.execute("""
                CREATE TABLE IF NOT EXISTS likes (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    pesquisa_id INTEGER NOT NULL REFERENCES pesquisas(id) ON DELETE CASCADE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(user_id, pesquisa_id)
                );
            """)

            # saves
            cur.execute("""
                CREATE TABLE IF NOT EXISTS saves (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    pesquisa_id INTEGER NOT NULL REFERENCES pesquisas(id) ON DELETE CASCADE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(user_id, pesquisa_id)
                );
            """)

            # índices
            cur.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_pesquisas_area ON pesquisas(area);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_pesquisas_pesquisador ON pesquisas(pesquisador);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_pesquisas_data ON pesquisas(data_publicacao);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_pesquisas_user ON pesquisas(pesquisador_id);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_likes_pesquisa ON likes(pesquisa_id);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_saves_pesquisa ON saves(pesquisa_id);")

        conn.commit()


try:
    init_db()
except Exception as e:
    print("Erro ao iniciar DB:", e)


# =========================================================
# HELPERS
# =========================================================
def normalize_original_link(raw: str) -> str:
    s = (raw or "").strip()
    if not s:
        return s
    lower = s.lower()

    # DOI puro
    if s.startswith("10.") and "/" in s:
        return "https://doi.org/" + s

    # doi.org/ sem esquema
    if lower.startswith("doi.org/"):
        return "https://" + s

    if lower.startswith("http://") or lower.startswith("https://"):
        return s

    return "https://" + s


def is_owner(p: dict) -> bool:
    return current_user.is_authenticated and int(p["pesquisador_id"]) == int(current_user.id)


def get_like_save_state(cur, pesquisa_id: int, user_id: int) -> tuple[bool, bool]:
    cur.execute("SELECT 1 FROM likes WHERE pesquisa_id=%s AND user_id=%s", (pesquisa_id, user_id))
    liked = cur.fetchone() is not None
    cur.execute("SELECT 1 FROM saves WHERE pesquisa_id=%s AND user_id=%s", (pesquisa_id, user_id))
    saved = cur.fetchone() is not None
    return liked, saved


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
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, email, nome, instituicao FROM users WHERE id = %s", (user_id,))
            row = cur.fetchone()
            if row:
                return User(row["id"], row["email"], row["nome"], row.get("instituicao"))
    return None


# =========================================================
# AUTH
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

        if REQUIRE_INVITE:
            codigo = (request.form.get("codigo_convite") or "").strip()
            if codigo != INVITE_CODE:
                flash("Código de convite inválido.", "error")
                return render_template("register.html", app_name=APP_NAME, require_invite=REQUIRE_INVITE)

        if not nome or not email or not senha:
            flash("Preencha nome, email e senha.", "error")
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
                cur.execute(
                    "INSERT INTO users (email, password, nome, instituicao) VALUES (%s, %s, %s, %s)",
                    (email, hashed, nome, instituicao)
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
            login_user(User(row["id"], row["email"], row["nome"], row.get("instituicao")), remember=True)
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
# VITRINE + BUSCA
# =========================================================
@app.route("/")
def index():
    filtro_area = (request.args.get("area") or "").strip()
    q = (request.args.get("q") or "").strip()

    where = []
    params = []

    if filtro_area and filtro_area in AREAS:
        where.append("p.area = %s")
        params.append(filtro_area)

    if q:
        where.append("(p.titulo ILIKE %s OR p.descoberta ILIKE %s OR p.pesquisador ILIKE %s)")
        like = f"%{q}%"
        params.extend([like, like, like])

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    sql = f"""
        SELECT
          p.*,
          COALESCE(l.likes_count, 0) AS likes_count,
          COALESCE(s.saves_count, 0) AS saves_count
        FROM pesquisas p
        LEFT JOIN (
          SELECT pesquisa_id, COUNT(*)::int AS likes_count
          FROM likes
          GROUP BY pesquisa_id
        ) l ON l.pesquisa_id = p.id
        LEFT JOIN (
          SELECT pesquisa_id, COUNT(*)::int AS saves_count
          FROM saves
          GROUP BY pesquisa_id
        ) s ON s.pesquisa_id = p.id
        {where_sql}
        ORDER BY p.id DESC
    """

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, tuple(params))
            pesquisas = cur.fetchall()

    return render_template(
        "index.html",
        app_name=APP_NAME,
        pesquisas=pesquisas,
        areas=AREAS,
        filtro_area=filtro_area,
        q=q
    )


# =========================================================
# PÁGINA INDIVIDUAL + VIEWS
# =========================================================
@app.route("/pesquisa/<int:pid>")
def pesquisa(pid):
    with get_conn() as conn:
        with conn.cursor() as cur:
            # incrementa views
            cur.execute("UPDATE pesquisas SET views = views + 1 WHERE id=%s", (pid,))
            conn.commit()

            # carrega a pesquisa + contagens
            cur.execute("""
                SELECT
                  p.*,
                  COALESCE(l.likes_count, 0) AS likes_count,
                  COALESCE(s.saves_count, 0) AS saves_count
                FROM pesquisas p
                LEFT JOIN (
                  SELECT pesquisa_id, COUNT(*)::int AS likes_count
                  FROM likes
                  GROUP BY pesquisa_id
                ) l ON l.pesquisa_id = p.id
                LEFT JOIN (
                  SELECT pesquisa_id, COUNT(*)::int AS saves_count
                  FROM saves
                  GROUP BY pesquisa_id
                ) s ON s.pesquisa_id = p.id
                WHERE p.id = %s
            """, (pid,))
            p = cur.fetchone()

            if not p:
                flash("Pesquisa não encontrada.", "error")
                return redirect(url_for("index"))

            liked = saved = False
            if current_user.is_authenticated:
                liked, saved = get_like_save_state(cur, pid, int(current_user.id))

    return render_template(
        "pesquisa.html",
        app_name=APP_NAME,
        p=p,
        liked=liked,
        saved=saved,
        owner=is_owner(p)
    )


# =========================================================
# LIKE / SAVE (TOGGLE)
# =========================================================
@app.route("/pesquisa/<int:pid>/like", methods=["POST"])
@login_required
def toggle_like(pid):
    with get_conn() as conn:
        with conn.cursor() as cur:
            # existe?
            cur.execute("SELECT 1 FROM likes WHERE pesquisa_id=%s AND user_id=%s", (pid, int(current_user.id)))
            if cur.fetchone():
                cur.execute("DELETE FROM likes WHERE pesquisa_id=%s AND user_id=%s", (pid, int(current_user.id)))
            else:
                cur.execute("INSERT INTO likes (pesquisa_id, user_id) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                            (pid, int(current_user.id)))
        conn.commit()
    return redirect(request.referrer or url_for("pesquisa", pid=pid))


@app.route("/pesquisa/<int:pid>/save", methods=["POST"])
@login_required
def toggle_save(pid):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM saves WHERE pesquisa_id=%s AND user_id=%s", (pid, int(current_user.id)))
            if cur.fetchone():
                cur.execute("DELETE FROM saves WHERE pesquisa_id=%s AND user_id=%s", (pid, int(current_user.id)))
            else:
                cur.execute("INSERT INTO saves (pesquisa_id, user_id) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                            (pid, int(current_user.id)))
        conn.commit()
    return redirect(request.referrer or url_for("pesquisa", pid=pid))


# =========================================================
# PUBLICAR
# =========================================================
@app.route("/publicar", methods=["GET", "POST"])
@login_required
def publicar():
    if request.method == "POST":
        titulo = (request.form.get("titulo") or "").strip()
        area = (request.form.get("area") or "").strip()
        descoberta = (request.form.get("descoberta") or "").strip()
        link_original_raw = (request.form.get("link_original") or "").strip()

        importancia = (request.form.get("importancia") or "").strip()
        aplicacao = (request.form.get("aplicacao") or "").strip()
        publico = (request.form.get("publico") or "").strip()
        evidencia = (request.form.get("evidencia") or "Inicial").strip()
        imagem_url = (request.form.get("imagem_url") or "").strip()

        if not titulo or not area or not descoberta or not link_original_raw:
            flash("Preencha os campos obrigatórios.", "error")
            return render_template("publicar.html", app_name=APP_NAME, areas=AREAS, evidencias=EVIDENCIAS, form=request.form)

        if area not in AREAS:
            area = "Humanas"
        if evidencia not in EVIDENCIAS:
            evidencia = "Inicial"

        link_original = normalize_original_link(link_original_raw)

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
                    importancia,
                    aplicacao,
                    publico,
                    evidencia,
                    link_original,
                    imagem_url
                ))
            conn.commit()

        flash("Pesquisa publicada com sucesso!", "success")
        return redirect(url_for("index"))

    return render_template("publicar.html", app_name=APP_NAME, areas=AREAS, evidencias=EVIDENCIAS, form={})


# =========================================================
# MINHAS + EDITAR + EXCLUIR
# =========================================================
@app.route("/minhas")
@login_required
def minhas_pesquisas():
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                  p.*,
                  COALESCE(l.likes_count, 0) AS likes_count,
                  COALESCE(s.saves_count, 0) AS saves_count
                FROM pesquisas p
                LEFT JOIN (
                  SELECT pesquisa_id, COUNT(*)::int AS likes_count
                  FROM likes
                  GROUP BY pesquisa_id
                ) l ON l.pesquisa_id = p.id
                LEFT JOIN (
                  SELECT pesquisa_id, COUNT(*)::int AS saves_count
                  FROM saves
                  GROUP BY pesquisa_id
                ) s ON s.pesquisa_id = p.id
                WHERE p.pesquisador_id = %s
                ORDER BY p.data_publicacao DESC
            """, (int(current_user.id),))
            pesquisas = cur.fetchall()

    return render_template("minhas.html", app_name=APP_NAME, pesquisas=pesquisas)


@app.route("/pesquisa/<int:pid>/editar", methods=["GET", "POST"])
@login_required
def editar_pesquisa(pid):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM pesquisas WHERE id = %s", (pid,))
            p = cur.fetchone()

        if not p:
            flash("Pesquisa não encontrada.", "error")
            return redirect(url_for("index"))

        if int(p["pesquisador_id"]) != int(current_user.id):
            flash("Você não tem permissão para editar essa pesquisa.", "error")
            return redirect(url_for("index"))

        if request.method == "POST":
            titulo = (request.form.get("titulo") or "").strip()
            area = (request.form.get("area") or "").strip()
            descoberta = (request.form.get("descoberta") or "").strip()
            link_original_raw = (request.form.get("link_original") or "").strip()

            importancia = (request.form.get("importancia") or "").strip()
            aplicacao = (request.form.get("aplicacao") or "").strip()
            publico = (request.form.get("publico") or "").strip()
            evidencia = (request.form.get("evidencia") or "Inicial").strip()
            imagem_url = (request.form.get("imagem_url") or "").strip()

            if not titulo or not area or not descoberta or not link_original_raw:
                flash("Preencha os campos obrigatórios.", "error")
                return render_template("editar.html", app_name=APP_NAME, areas=AREAS, evidencias=EVIDENCIAS, p=p)

            if area not in AREAS:
                area = "Humanas"
            if evidencia not in EVIDENCIAS:
                evidencia = "Inicial"

            link_original = normalize_original_link(link_original_raw)

            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE pesquisas
                    SET
                      titulo=%s,
                      area=%s,
                      descoberta=%s,
                      importancia=%s,
                      aplicacao=%s,
                      publico=%s,
                      evidencia=%s,
                      link_original=%s,
                      imagem_url=%s,
                      updated_at=NOW()
                    WHERE id=%s AND pesquisador_id=%s
                """, (
                    titulo, area, descoberta, importancia, aplicacao, publico,
                    evidencia, link_original, imagem_url,
                    int(pid), int(current_user.id)
                ))
            conn.commit()

            flash("Pesquisa atualizada!", "success")
            return redirect(url_for("minhas_pesquisas"))

    return render_template("editar.html", app_name=APP_NAME, areas=AREAS, evidencias=EVIDENCIAS, p=p)


@app.route("/pesquisa/<int:pid>/excluir", methods=["POST"])
@login_required
def excluir_pesquisa(pid):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM pesquisas WHERE id=%s AND pesquisador_id=%s", (int(pid), int(current_user.id)))
        conn.commit()
    flash("Pesquisa excluída.", "success")
    return redirect(url_for("minhas_pesquisas"))


# =========================================================
# PERFIL / SOBRE
# =========================================================
@app.route("/perfil/<nome>")
def perfil(nome):
    nome = (nome or "").strip()
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                  p.*,
                  COALESCE(l.likes_count, 0) AS likes_count,
                  COALESCE(s.saves_count, 0) AS saves_count
                FROM pesquisas p
                LEFT JOIN (
                  SELECT pesquisa_id, COUNT(*)::int AS likes_count
                  FROM likes
                  GROUP BY pesquisa_id
                ) l ON l.pesquisa_id = p.id
                LEFT JOIN (
                  SELECT pesquisa_id, COUNT(*)::int AS saves_count
                  FROM saves
                  GROUP BY pesquisa_id
                ) s ON s.pesquisa_id = p.id
                WHERE p.pesquisador = %s
                ORDER BY p.id DESC
            """, (nome,))
            pesquisas = cur.fetchall()

    return render_template("perfil.html", app_name=APP_NAME, pesquisas=pesquisas, nome=nome)


@app.route("/sobre")
def sobre():
    return render_template("sobre.html", app_name=APP_NAME, codigo_exemplo=(INVITE_CODE if REQUIRE_INVITE else ""))


# =========================================================
# RUN
# =========================================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    debug = os.environ.get("FLASK_DEBUG", "0").strip().lower() in ("1", "true", "yes")
    app.run(host="0.0.0.0", port=port, debug=debug)
