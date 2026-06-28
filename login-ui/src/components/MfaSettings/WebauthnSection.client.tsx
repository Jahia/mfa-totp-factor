import { useEffect, useRef, useState } from "react";
import { Trans, useTranslation } from "react-i18next";
import { useApiRoot } from "../../hooks/ApiRootContext";
import {
  deleteWebauthnCredential,
  finishRegistrationWebauthn,
  renameWebauthnCredential,
  startRegistrationWebauthn,
  webauthnStatus,
} from "../../services";
import type { WebauthnCredential } from "../../services/webauthnStatus";
import { createCredential, isWebauthnSupported } from "../../services/webauthnBrowser";
import { translateError } from "../../services/i18n";
import classes from "../Authentication/component.module.css";
import ErrorMessage from "../Authentication/ErrorMessage.client";

/** Render an ISO timestamp as a locale date, or a dash when absent. */
function formatDate(value: string | null): string {
  if (!value) {
    return "-";
  }
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value : d.toLocaleDateString();
}

/**
 * Self-service WebAuthn passkey management: list registered credentials, add a new one (a single
 * registration ceremony — post-auth there is no assertion "second touch"), rename, and remove.
 * Every op is scoped server-side to the logged-in user.
 */
export default function WebauthnSection() {
  const { t } = useTranslation();
  const apiRoot = useApiRoot();
  const supported = isWebauthnSupported();

  const [loading, setLoading] = useState(true);
  const [credentials, setCredentials] = useState<WebauthnCredential[]>([]);
  const [platformSupported, setPlatformSupported] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [renamingId, setRenamingId] = useState<string | null>(null);
  const [renameValue, setRenameValue] = useState("");
  const headingRef = useRef<HTMLHeadingElement>(null);

  const load = () => {
    webauthnStatus(apiRoot).then((res) => {
      if (res.success) {
        setPlatformSupported(res.supported);
        setCredentials(res.credentials);
      } else {
        setError(translateError(t, res.error));
      }
      setLoading(false);
    });
  };

  useEffect(() => {
    load();
    // Load once on mount.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const addPasskey = async () => {
    setBusy(true);
    setError("");
    try {
      const start = await startRegistrationWebauthn(apiRoot);
      if (!start.success) {
        setError(translateError(t, start.error));
        return;
      }
      const attestation = await createCredential(start.creationOptionsJson);
      const finish = await finishRegistrationWebauthn(apiRoot, attestation);
      if (!finish.success) {
        setError(translateError(t, finish.error));
        return;
      }
      load();
    } catch (e) {
      setError(
        t(
          (e as DOMException)?.name === "NotAllowedError"
            ? "factor.webauthn.cancelled"
            : "enroll.webauthn.failed",
        ),
      );
    } finally {
      setBusy(false);
    }
  };

  const submitRename = (credentialId: string) => {
    const nickname = renameValue.trim();
    if (!nickname) return;
    setBusy(true);
    setError("");
    renameWebauthnCredential(apiRoot, credentialId, nickname)
      .then((res) => {
        if (res.success) {
          setRenamingId(null);
          setRenameValue("");
          load();
        } else {
          setError(translateError(t, res.error));
        }
      })
      .finally(() => setBusy(false));
  };

  const remove = (credentialId: string, label: string) => {
    if (!window.confirm(t("settings.webauthn.removeConfirm", { name: label }))) {
      return;
    }
    setBusy(true);
    setError("");
    deleteWebauthnCredential(apiRoot, credentialId)
      .then((res) => {
        if (res.success) {
          load();
        } else {
          setError(translateError(t, res.error));
        }
      })
      .finally(() => setBusy(false));
  };

  const wrap = (children: React.ReactNode) => (
    <section
      aria-labelledby="mfa-webauthn-heading"
      data-testid="mfa-webauthn-section"
      className={classes.mfaSection}
    >
      <h2 id="mfa-webauthn-heading" ref={headingRef} tabIndex={-1}>
        <Trans i18nKey="settings.webauthn.heading" />
      </h2>
      {children}
    </section>
  );

  if (loading) {
    return wrap(
      <div role="status" aria-live="polite" className={classes.helpText}>
        <Trans i18nKey="settings.loading" />
      </div>,
    );
  }

  if (!supported || !platformSupported) {
    return wrap(
      <p className={classes.helpText} role="alert" data-testid="mfa-webauthn-unsupported">
        <Trans i18nKey="factor.webauthn.unsupported" />
      </p>,
    );
  }

  return wrap(
    <>
      {credentials.length === 0 ? (
        <p className={classes.helpText} data-testid="mfa-webauthn-empty">
          <Trans i18nKey="settings.webauthn.noCredentials" />
        </p>
      ) : (
        <ul className={classes.credentialList} data-testid="mfa-webauthn-credentials">
          {credentials.map((c) => {
            const label = c.nickname || t("settings.webauthn.unnamed");
            return (
              <li key={c.credentialId} className={classes.credentialRow}>
                {renamingId === c.credentialId ? (
                  <div className={classes.credentialMain}>
                    <input
                      type="text"
                      className={classes.backupCodeInput}
                      data-testid="mfa-webauthn-rename-input"
                      aria-label={t("settings.webauthn.renamePrompt")}
                      value={renameValue}
                      disabled={busy}
                      onChange={(e) => setRenameValue(e.target.value)}
                    />
                    <div className={classes.mfaActions}>
                      <button
                        type="button"
                        className={classes.submitButton}
                        data-testid="mfa-webauthn-rename-save"
                        disabled={!renameValue.trim() || busy}
                        onClick={() => submitRename(c.credentialId)}
                      >
                        {t("settings.confirm")}
                      </button>
                      <button
                        type="button"
                        className={classes.secondaryButton}
                        data-testid="mfa-webauthn-rename-cancel"
                        onClick={() => {
                          setRenamingId(null);
                          setRenameValue("");
                        }}
                      >
                        {t("settings.cancel")}
                      </button>
                    </div>
                  </div>
                ) : (
                  <>
                    <div className={classes.credentialMain}>
                      <span className={classes.credentialName} data-testid="mfa-webauthn-name">
                        {label}
                      </span>
                      <span className={classes.helpText}>
                        {t("settings.webauthn.created", { date: formatDate(c.createdAt) })}
                        {" · "}
                        {t("settings.webauthn.lastUsed", { date: formatDate(c.lastUsedAt) })}
                      </span>
                    </div>
                    <div className={classes.mfaActions}>
                      <button
                        type="button"
                        className={classes.secondaryButton}
                        data-testid="mfa-webauthn-rename"
                        disabled={busy}
                        onClick={() => {
                          setRenamingId(c.credentialId);
                          setRenameValue(c.nickname || "");
                        }}
                      >
                        {t("settings.webauthn.rename")}
                      </button>
                      <button
                        type="button"
                        className={classes.dangerButton}
                        data-testid="mfa-webauthn-remove"
                        disabled={busy}
                        onClick={() => remove(c.credentialId, label)}
                      >
                        {t("settings.webauthn.remove")}
                      </button>
                    </div>
                  </>
                )}
              </li>
            );
          })}
        </ul>
      )}
      <ErrorMessage message={error} id="mfa-webauthn-error" />
      <div style={{ textAlign: "center", marginTop: "0.5rem" }}>
        <button
          type="button"
          className={classes.submitButton}
          data-testid="mfa-webauthn-add"
          disabled={busy}
          aria-busy={busy}
          onClick={addPasskey}
        >
          {busy ? t("factor.webauthn.inProgress") : t("settings.webauthn.add")}
        </button>
      </div>
    </>,
  );
}
