import { type FormEvent, useState } from "react";
import { initiate } from "../../services";
import classes from "./component.module.css";
import { useApiRoot } from "../../hooks/ApiRootContext";
import ErrorMessage from "./ErrorMessage.client";
import type { Props } from "./types";
import { convertErrorArgsToInterpolation } from "../../services/i18n";
import type { MfaError } from "../../services/common";
import { Trans, useTranslation } from "react-i18next";
import { submitOnEnter } from "./formKeyboard";

function extractSiteKeyFromUrl(): string | undefined {
  const url = globalThis.location.pathname;
  const match = new RegExp(/^\/sites\/([^/]+)/).exec(url);
  if (!match) {
    return undefined;
  }
  return match[1];
}

interface LoginFormProps {
  content: Props;
  onSuccess: (info: {username: string; remainingFactors: string[]}) => void;
  onAllFactorsCompleted: () => void;
  onFatalError: (error: MfaError) => void;
}

export default function LoginForm(props: Readonly<LoginFormProps>) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [inProgress, setInProgress] = useState(false);
  const apiRoot = useApiRoot();
  const { t } = useTranslation();

  const submit = () => {
    if (inProgress) return;
    setInProgress(true);

    // The server-resolved site key is authoritative; the URL heuristic only works for
    // /sites/<key>/... paths and fails on vanity/server-name URLs.
    const site = props.content.siteKey || extractSiteKeyFromUrl();

    // No "remember me" option: always a session-scoped login (no persistent auth cookie).
    initiate(apiRoot, username, password, false, site)
      .then((result) => {
        if (result.success) {
          if (result.remainingFactors.length === 0) {
            props.onAllFactorsCompleted();
          } else {
            props.onSuccess({username, remainingFactors: result.remainingFactors});
          }
          setError("");
        } else if (result?.fatalError) {
          props.onFatalError(result.error);
        } else {
          const { key, interpolation } = convertErrorArgsToInterpolation(result.error);
          setError(t(key, interpolation));
        }
      })
      .finally(() => setInProgress(false));
  };

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    submit();
  };

  return (
    <>
      {/* Every step of the flow opens with a heading (WCAG 2.4.10 Section Headings). */}
      <h2>
        <Trans i18nKey="login.title" />
      </h2>
      <form onSubmit={handleSubmit}>
        <div className={classes.formField}>
          <label htmlFor="username">{props.content.loginEmailFieldLabel}</label>
          <input
            id="username"
            name="username"
            type="text"
            autoComplete="username"
            data-testid="login-username"
            onChange={(e) => setUsername(e.target.value)}
            onKeyDown={submitOnEnter(submit)}
          />
        </div>
        <div className={classes.formField}>
          <label htmlFor="password">{props.content.loginPasswordFieldLabel}</label>
          <input
            id="password"
            name="password"
            type="password"
            autoComplete="current-password"
            data-testid="login-password"
            onChange={(e) => setPassword(e.target.value)}
            onKeyDown={submitOnEnter(submit)}
          />
        </div>
        {props.content.loginBelowPasswordFieldHtml && (
          <div
            data-testid="below-password-field"
            className={classes.belowPasswordField}
            dangerouslySetInnerHTML={{ __html: props.content.loginBelowPasswordFieldHtml }}
          />
        )}
        <ErrorMessage message={error} />
        <button
          type="submit"
          disabled={inProgress}
          data-testid="login-submit"
          className={classes.submitButton}
        >
          {props.content.loginSubmitButtonLabel}
        </button>
      </form>
      <hr />
      {props.content.loginAdditionalActionHtml && (
        <div
          data-testid="additional-action"
          className={classes.additionalAction}
          dangerouslySetInnerHTML={{ __html: props.content.loginAdditionalActionHtml }}
        />
      )}
    </>
  );
}
