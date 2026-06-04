import { type ChangeEvent, type FormEvent, useEffect, useRef, useState } from "react";
import { useApiRoot } from "../../hooks/ApiRootContext";
import { prepareEmailFactor, verifyEmailCodeFactor } from "../../services";
import classes from "./component.module.css";
import ErrorMessage from "./ErrorMessage.client";
import { convertErrorArgsToInterpolation } from "../../services/i18n";
import { Trans, useTranslation } from "react-i18next";
import type { MfaError } from "../../services/common";
import { submitOnEnter } from "./formKeyboard";

interface EmailCodeVerificationFormProps {
  onSuccess: () => void;
  onFatalError: (error: MfaError) => void;
}

const CODE_LENGTH = 6;

export default function EmailCodeVerificationForm(
  props: Readonly<EmailCodeVerificationFormProps>,
) {
  const { t } = useTranslation();
  const apiRoot = useApiRoot();
  const inputRef = useRef<HTMLInputElement>(null);
  const [loading, setLoading] = useState(true);
  const [maskedEmail, setMaskedEmail] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const prepare = () => {
    setLoading(true);
    prepareEmailFactor(apiRoot)
      .then((result) => {
        if (result.success) {
          setError("");
          setMaskedEmail(result.maskedEmail);
        } else if (result?.fatalError) {
          props.onFatalError(result.error);
        } else {
          const { key, interpolation } = convertErrorArgsToInterpolation(result.error);
          setError(t(key, interpolation));
        }
      })
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    inputRef.current?.focus();
    prepare();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (loading) {
    return (
      <div>
        <Trans i18nKey="verify.loading" />
      </div>
    );
  }

  const handleCodeChange = (e: ChangeEvent<HTMLInputElement>) => {
    setCode(e.target.value.replace(/\D/g, "").slice(0, CODE_LENGTH));
  };

  const submit = () => {
    if (code.length !== CODE_LENGTH || submitting) return;
    setSubmitting(true);
    verifyEmailCodeFactor(apiRoot, code)
      .then((result) => {
        if (result.success) {
          setError("");
          props.onSuccess();
        } else if (result?.fatalError) {
          props.onFatalError(result.error);
        } else {
          const { key, interpolation } = convertErrorArgsToInterpolation(result.error);
          setError(t(key, interpolation));
        }
      })
      .finally(() => setSubmitting(false));
  };

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    submit();
  };

  return (
    <div className={classes.otpFormWrapper}>
      <h2>
        <Trans i18nKey="factor.email_code.title" />
      </h2>
      {maskedEmail && (
        <p className={classes.helpText}>
          <Trans
            i18nKey="factor.email_code.verification_code_has_been_sent"
            components={{ mark: <strong /> }}
            values={{ maskedEmail }}
          />
        </p>
      )}
      <form onSubmit={handleSubmit}>
        <div style={{ textAlign: "center" }}>
          <input
            ref={inputRef}
            id="emailVerificationCode"
            name="emailVerificationCode"
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            placeholder="123456"
            value={code}
            onChange={handleCodeChange}
            onKeyDown={submitOnEnter(submit)}
            aria-label="Enter email verification code"
            data-testid="email-verification-code"
            className={classes.otpInput}
            required
          />
        </div>
        <ErrorMessage message={error} />
        <div style={{ textAlign: "center", marginTop: "0.5rem" }}>
          <button
            type="submit"
            disabled={code.length !== CODE_LENGTH || submitting}
            data-testid="email-verification-submit"
            className={classes.submitButton}
          >
            <Trans i18nKey="factor.email_code.verify" />
          </button>
        </div>
        <hr />
        <div className={classes.additionalAction}>
          <button
            type="button"
            className={classes.toggleMode}
            data-testid="email-resend"
            onClick={prepare}
          >
            <Trans i18nKey="factor.email_code.resend" />
          </button>
        </div>
      </form>
    </div>
  );
}
