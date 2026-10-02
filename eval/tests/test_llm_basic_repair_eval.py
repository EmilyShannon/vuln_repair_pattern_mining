import sys
from pathlib import Path

repo_root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(repo_root))
from eval.evaluate_results import compute_diff, compute_fuzzy_match, compute_bleu, compute_codebleu, normalize_patch
import codebleu
print(codebleu.AVAILABLE_LANGS)

gt_patch = """cockpit_auth_login_finish (CockpitAuth *self,
                           GAsyncResult *result,
                           GIOStream *connection,
                           GHashTable *headers,
                           GError **error)
{
  JsonObject *body = NULL;
  CockpitCreds *creds = NULL;
  CockpitSession *session = NULL;
  gboolean force_secure;
  gchar *cookie_name;
  gchar *cookie_b64;
  gchar *header;
  gchar *id;

  g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (self),
                        cockpit_auth_login_async), NULL);

  g_object_ref (result);
  session = g_simple_async_result_get_op_res_gpointer (G_SIMPLE_ASYNC_RESULT (result));

  if (g_simple_async_result_propagate_error (G_SIMPLE_ASYNC_RESULT (result), error))
    goto out;

  g_return_val_if_fail (session != NULL, NULL);
  g_return_val_if_fail (session->result == NULL, NULL);

  cockpit_session_reset (session);

  if (session->authorize)
    {
      if (build_authorize_challenge (self, session->authorize, connection,
                                     headers, &body, &session->conversation))
        {
          if (session->conversation)
            {
              reset_authorize_timeout (session, TRUE);
              g_hash_table_replace (self->conversations, session->conversation, cockpit_session_ref (session));
            }
        }
    }

  if (session->initialized)
    {
      /* Start off in the idling state, and begin a timeout during which caller must do something else */
      on_web_service_idling (session->service, session);
      creds = cockpit_web_service_get_creds (session->service);

      id = cockpit_auth_nonce (self);
      session->cookie = g_strdup_printf (""v=2;k=%s"", id);
      g_hash_table_insert (self->sessions, session->cookie, cockpit_session_ref (session));
      g_free (id);

      if (headers)
        {
          if (self->flags & COCKPIT_AUTH_FOR_TLS_PROXY)
            force_secure = TRUE;
          else
            force_secure = connection ? !G_IS_SOCKET_CONNECTION (connection) : TRUE;
          cookie_name = application_cookie_name (cockpit_creds_get_application (creds));
          cookie_b64 = g_base64_encode ((guint8 *)session->cookie, strlen (session->cookie));
          header = g_strdup_printf (""%s=%s; Path=/; %s HttpOnly"",
                                    cookie_name, cookie_b64,
                                    force_secure ? "" Secure;"" : "");
          g_free (cookie_b64);
          g_free (cookie_name);
          g_hash_table_insert (headers, g_strdup (""Set-Cookie""), header);
        }

      if (body)
        json_object_unref (body);
      body = cockpit_creds_to_json (creds);
    }
  else
    {
      g_set_error (error, COCKPIT_ERROR, COCKPIT_ERROR_AUTHENTICATION_FAILED,
                   ""Authentication failed"");
    }

out:
  self->startups--;
  g_object_unref (result);

  /* Successful login */
  if (creds)
    g_info (""User %s logged into session %s"",
            cockpit_creds_get_user (creds),
            cockpit_web_service_get_id (session->service));

  return body;
}"""

patch_with_carriage_returns = """cockpit_auth_login_finish (CockpitAuth *self,
                           GAsyncResult *result,
                           GIOStream *connection,
                           GHashTable *headers,
                           GError **error)
{
  JsonObject *body = NULL;
  CockpitCreds *creds = NULL;
  CockpitSession *session = NULL;
  gboolean force_secure;
  gchar *cookie_name;
  gchar *cookie_b64;
  gchar *header;
  gchar *id;

  g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (self),
                        cockpit_auth_login_async), NULL);

  g_object_ref (result);
  session = g_simple_async_result_get_op_res_gpointer (G_SIMPLE_ASYNC_RESULT (result));

  if (g_simple_async_result_propagate_error (G_SIMPLE_ASYNC_RESULT (result), error))
    goto out;

  g_return_val_if_fail (session != NULL, NULL);
  g_return_val_if_fail (session->result == NULL, NULL);

  cockpit_session_reset (session); \r

  if (session->authorize)
    {
      if (build_authorize_challenge (self, session->authorize, connection,
                                     headers, &body, &session->conversation))
        {
          if (session->conversation)
            {
              reset_authorize_timeout (session, TRUE);
              g_hash_table_replace (self->conversations, session->conversation, cockpit_session_ref (session));
            }
        }
    }

  if (session->initialized)
    {
      /* Start off in the idling state, and begin a timeout during which caller must do something else */
      on_web_service_idling (session->service, session);
      creds = cockpit_web_service_get_creds (session->service);

      id = cockpit_auth_nonce (self);
      session->cookie = g_strdup_printf (""v=2;k=%s"", id);
      g_hash_table_insert (self->sessions, session->cookie, cockpit_session_ref (session));
      g_free (id);

      if (headers)                              
        {
          if (self->flags & COCKPIT_AUTH_FOR_TLS_PROXY)
            force_secure = TRUE;
          else
            force_secure = connection ? !G_IS_SOCKET_CONNECTION (connection) : TRUE;
          cookie_name = application_cookie_name (cockpit_creds_get_application (creds));
          cookie_b64 = g_base64_encode ((guint8 *)session->cookie, strlen (session->cookie));
          header = g_strdup_printf (""%s=%s; Path=/; %s HttpOnly"",
                                    cookie_name, cookie_b64,
                                    force_secure ? "" Secure;"" : "");
          g_free (cookie_b64);
          g_free (cookie_name);
          g_hash_table_insert (headers, g_strdup (""Set-Cookie""), header);
        }

      if (body)
        json_object_unref (body);
      body = cockpit_creds_to_json (creds);
    }
  else
    {
      g_set_error (error, COCKPIT_ERROR, COCKPIT_ERROR_AUTHENTICATION_FAILED,
                   ""Authentication failed"");
    }

out:
  self->startups--;
  g_object_unref (result);

  /* Successful login */
  if (creds)
    g_info (""User %s logged into session %s"",
            cockpit_creds_get_user (creds),
            cockpit_web_service_get_id (session->service));

  return body;
}"""

patch_to_eval="""cockpit_auth_login_finish (CockpitAuth *self,
                           GAsyncResult *result,
                           GIOStream *connection,
                           GHashTable *headers,
                           GError **error)
{
  JsonObject *body = NULL;
  CockpitCreds *creds = NULL;
  CockpitSession *session = NULL;
  gboolean force_secure;
  gchar *cookie_name;
  gchar *cookie_b64;
  gchar *header;
  gchar *id;

  g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (self),
                        cockpit_auth_login_async), NULL);

  g_object_ref (result);
  session = g_simple_async_result_get_op_res_gpointer (G_SIMPLE_ASYNC_RESULT (result));

  if (g_simple_async_result_propagate_error (G_SIMPLE_ASYNC_RESULT (result), error))
    goto out;

  g_return_val_if_fail (session != NULL, NULL);
  g_return_val_if_fail (session->result == NULL, NULL);

  cockpit_session_reset (session);

  if (session->authorize)
    {
      if (build_authorize_challenge (self, session->authorize, connection,
                                     headers, &body, &session->conversation))
        {
          if (session->conversation)
            {
              reset_authorize_timeout (session, TRUE);
              g_hash_table_replace (self->conversations, session->conversation, cockpit_session_ref (session));
            }
        }
    }

  if (session->initialized)
    {
      /* Start off in the idling state, and begin a timeout during which caller must do something else */
      on_web_service_idling (session->service, session);
      creds = cockpit_web_service_get_creds (session->service);

      id = cockpit_auth_nonce (self);
      session->cookie = g_strdup_printf (""v=2;k=%s"", id);
      g_hash_table_insert (self->sessions, session->cookie, cockpit_session_ref (session));
      g_free (id);

      if (headers)
        {
          if (self->flags & COCKPIT_AUTH_FOR_TLS_PROXY)
            force_secure = TRUE;
          else
            force_secure = connection ? !G_IS_SOCKET_CONNECTION (connection) : TRUE;
          cookie_name = application_cookie_name (cockpit_creds_get_application (creds));
          /* Sanitize cookie name to prevent HTTP header injection (e.g., CRLF, semicolons) */
          g_strdelimit (cookie_name, ""\r\n;=, "", '_');
          cookie_b64 = g_base64_encode ((guint8 *)session->cookie, strlen (session->cookie));
          header = g_strdup_printf (""%s=%s; Path=/; %s HttpOnly"",
                                    cookie_name, cookie_b64,
                                    force_secure ? "" Secure;"" : "");
          g_free (cookie_b64);
          g_free (cookie_name);
          g_hash_table_insert (headers, g_strdup (""Set-Cookie""), header);
        }

      if (body)
        json_object_unref (body);
      body = cockpit_creds_to_json (creds);
    }
  else
    {
      g_set_error (error, COCKPIT_ERROR, COCKPIT_ERROR_AUTHENTICATION_FAILED,
                   ""Authentication failed"");
    }

out:
  self->startups--;
  g_object_unref (result);

  /* Successful login */
  if (creds)
    g_info (""User %s logged into session %s"",
            cockpit_creds_get_user (creds),
            cockpit_web_service_get_id (session->service));

  return body;
}"""

unnormalized = """if ( x == 42 ) {
    printf("Hello, world!\n");
}"""

normalized = """if(x==42){
printf("Hello,world!\n");
}"""

def test_normalize_patch():
    # print(normalize_patch(unnormalized))
    assert normalize_patch(unnormalized) == normalized, "Normalized strings do not match"

def test_compute_bleu_identical_patches():
    bleu_score = compute_bleu(normalize_patch(unnormalized), normalize_patch(normalized))
    # print(f"BLEU score (identical): {bleu_score}")
    assert bleu_score == 1.0, f"BLEU score for identical patches should be 1.0: {bleu_score}"

def test_compute_bleu_unmatched_patches():
    bleu_score = compute_bleu(gt_patch, patch_to_eval)
    # print(f"BLEU score: {bleu_score}")
    assert bleu_score > 0.8, f"BLEU score is too low: {bleu_score}"

def test_compute_codebleu_identical_patches():
    codebleu_score = compute_codebleu(normalize_patch(unnormalized), normalize_patch(normalized))
    # print(f"CodeBLEU score (identical): {codebleu_score}")
    assert codebleu_score == 1.0, f"CodeBLEU score for identical patches should be 1.0: {codebleu_score}"

def test_compute_codebleu_unmatched_patches():
    codebleu_score = compute_codebleu(gt_patch, patch_to_eval)
    # print(f"CodeBLEU score: {codebleu_score}")
    assert codebleu_score > 0.8, f"CodeBLEU score is too low: {codebleu_score}"

def test_compute_fuzzy_match_identical_patches():
    fuzzy_match_score = compute_fuzzy_match(normalize_patch(unnormalized), normalize_patch(normalized))
    # print(f"Fuzzy match score (identical): {fuzzy_match_score}")
    assert fuzzy_match_score == 1.0, f"Fuzzy match score for identical patches should be 1.0: {fuzzy_match_score}"

def test_compute_fuzzy_match_unmatched_patches():
    fuzzy_match_score = compute_fuzzy_match(gt_patch, patch_to_eval)
    # print(f"Fuzzy match score: {fuzzy_match_score}")
    assert fuzzy_match_score > 0.8, f"Fuzzy match score is too low: {fuzzy_match_score}"

if __name__ == "__main__":
    print(compute_diff(gt_patch, patch_to_eval))
    test_normalize_patch()
    test_compute_bleu_identical_patches()
    test_compute_bleu_unmatched_patches()
    test_compute_codebleu_identical_patches()
    test_compute_codebleu_unmatched_patches()
    test_compute_fuzzy_match_identical_patches()
    test_compute_fuzzy_match_unmatched_patches()
    print("All tests passed.")