import { useState } from "react";
import { Trans, useTranslation } from "react-i18next";
import { useApiRoot } from "../../hooks/ApiRootContext";
import { requestMfaReset } from "../../services";
import { translateError } from "../../services/i18n";
import classes from "./component.module.css";
import ErrorMessage from "./ErrorMessage.client";

/**
 * "Lost access to your second factor?" affordance shown at the MFA verification step. A user who
 * passed their password but cannot complete any factor can request that an administrator reset
 * their MFA. The request carries no user input (the server uses the active session), and the
 * confirmation is deliberately generic.
 */
export default function RequestReset() {
  const { t } = useTranslation();
  const apiRoot = useApiRoot();
  const [open, setOpen] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState("");

  const submit = () => {
    if (submitting) return;
    setSubmitting(true);
    setError("");
    requestMfaReset(apiRoot)
      .then((res) => {
        if (res.success) {
          setDone(true);
        } else {
          setError(translateError(t, res.error));
        }
      })
      .finally(() => setSubmitting(false));
  };

  if (done) {
    return (
      <p
        role="status"
        aria-live="polite"
        className={classes.helpText}
        data-testid="reset-request-confirmation"
      >
        <Trans i18nKey="reset.request.confirmation" />
      </p>
    );
  }

  return (
    <div className={classes.additionalAction}>
      {open ? (
        <>
          <p className={classes.helpText}>
            <Trans i18nKey="reset.request.prompt" />
          </p>
          <ErrorMessage message={error} id="reset-request-error" />
          <button
            type="button"
            className={classes.secondaryButton}
            data-testid="reset-request-submit"
            disabled={submitting}
            aria-busy={submitting}
            aria-describedby="reset-request-error"
            onClick={submit}
          >
            {submitting ? t("reset.request.submitting") : t("reset.request.button")}
          </button>
        </>
      ) : (
        <button
          type="button"
          className={classes.toggleMode}
          data-testid="reset-request-open"
          onClick={() => setOpen(true)}
        >
          <Trans i18nKey="reset.request.lostAccess" />
        </button>
      )}
    </div>
  );
}
