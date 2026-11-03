# auth_ui.py
# -*- coding: utf-8 -*-
import streamlit as st
import hmac
from supabase_client import supabase_anon, supabase_authed
from bootstrap_db import ensure_user_seeded

def auth_gate():
    sb = supabase_anon()

    if "session" not in st.session_state:
        st.session_state["session"] = None
        st.session_state["user"] = None

    if st.session_state["session"] is None:
        # Acesso temporario da feira: o codigo na URL nao contem a senha.
        codigo_url = st.query_params.get("feira", "")
        codigo_config = st.secrets.get("FEIRA_ACCESS_CODE", "")
        if (isinstance(codigo_url, str) and codigo_url and codigo_config
                and hmac.compare_digest(codigo_url, str(codigo_config))):
            try:
                res = sb.auth.sign_in_with_password({
                    "email": st.secrets["FEIRA_EMAIL"],
                    "password": st.secrets["FEIRA_PASSWORD"],
                })
                if not res.session or not res.user:
                    raise RuntimeError("O Supabase nao retornou uma sessao valida.")
                sb_user = supabase_authed(res.session.access_token)
                ensure_user_seeded(sb_user, res.user.id)
                st.session_state["access_token"] = res.session.access_token
                st.session_state["session"] = res.session
                st.session_state["user"] = res.user
                # Remove o codigo do endereco depois do login.
                st.query_params.clear()
                st.rerun()
            except Exception:
                st.error("Nao foi possivel entrar no modo feira. Verifique a conta e os Secrets.")
                st.stop()
        st.subheader("Entrar / Criar conta")
        tab_login, tab_signup = st.tabs(["Login", "Criar conta"])

        with tab_login:
            email = st.text_input("Email", key="login_email")
            senha = st.text_input("Senha", type="password", key="login_senha")
            if st.button("Entrar", key="btn_login"):
                try:
                    res = sb.auth.sign_in_with_password({"email": email, "password": senha})

                    # ✅ guarda token para o resto do app
                    st.session_state["access_token"] = res.session.access_token

                    sb_user = supabase_authed(res.session.access_token)
                    ensure_user_seeded(sb_user, res.user.id)

                    st.session_state["session"] = res.session
                    st.session_state["user"] = res.user
                    st.rerun()
                except Exception as e:
                    st.error(f"Falha no login: {e}")

        with tab_signup:
            email = st.text_input("Email", key="signup_email")
            senha = st.text_input("Senha", type="password", key="signup_senha")
            if st.button("Criar conta", key="btn_signup"):
                try:
                    sb.auth.sign_up({"email": email, "password": senha})
                    st.success("Conta criada! Agora faça login na aba Login.")
                except Exception as e:
                    st.error(f"Falha ao criar conta: {e}")

        st.stop()

    user = st.session_state["user"]

    if st.button("Sair", key="btn_logout"):
        try:
            sb.auth.sign_out()
        except Exception:
            pass
        st.session_state["session"] = None
        st.session_state["user"] = None
        st.session_state.pop("access_token", None)  # ✅ limpa token
        st.rerun()

    return user.id
