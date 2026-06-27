import { type RefObject, useMemo, useState } from "react";
import { useApiRoot } from "../../hooks/ApiRootContext";
import classes from "./component.module.css";
import ErrorMessage from "./ErrorMessage.client";
import { convertErrorArgsToInterpolation } from "../../services/i18n";
import { Trans, useTranslation } from "react-i18next";
import { clear } from "../../services";
import type { MfaError } from "../../services/common";

interface FatalErrorScreenProps {
  error: MfaError;
  onResetFlow: () => void;
  /** Focus target for step-change focus management (WCAG 2.4.3). */
  headingRef?: RefObject<HTMLHeadingElement | null>;
}

const suspendedUserErrorCode = "suspended_user";

export default function FatalErrorScreen({
  error,
  onResetFlow,
  headingRef,
}: Readonly<FatalErrorScreenProps>) {
  const { t } = useTranslation();
  const [inProgress, setInProgress] = useState(false);
  const apiRoot = useApiRoot();

  const errorMessage = useMemo(() => {
    if (error.code === suspendedUserErrorCode) {
      const suspensionDurationInSecondsArg = error.arguments?.find(
        (arg) => arg.name === "suspensionDurationInSeconds",
      )?.value;
      const suspensionDurationInHours = suspensionDurationInSecondsArg
        ? Math.ceil(Number(suspensionDurationInSecondsArg) / 3600)
        : 0;
      return t(suspendedUserErrorCode, { suspensionDurationInHours });
    }
    // Unmapped server codes degrade to the generic message instead of rendering a raw machine
    // string (item 14).
    return t(error.code, {
      defaultValue: t("unexpected_error"),
      ...error.arguments?.reduce(
        (acc, arg) => ({ ...acc, [arg.name]: arg.value }),
        {} as Record<string, string>,
      ),
    });
  }, [error, t]);

  const [message, setMessage] = useState(errorMessage);

  function restartLogin() {
    setInProgress(true);
    clear(apiRoot)
      .then((result) => {
        if (result.success) {
          setMessage("");
          onResetFlow();
        } else {
          const { key, interpolation } = convertErrorArgsToInterpolation(result.error);
          setMessage(t(key, { defaultValue: t("unexpected_error"), ...interpolation }));
        }
      })
      .catch(() => setMessage(t("network_error")))
      .finally(() => setInProgress(false));
  }

  return (
    <>
      {/* Every step of the flow opens with a heading (WCAG 2.4.10 Section Headings). */}
      <h2 ref={headingRef} tabIndex={-1}>
        <Trans i18nKey="fatal.title" />
      </h2>
      {message && <ErrorMessage message={message} />}
      <hr aria-hidden="true" />
      <div data-testid="additional-action" className={classes.additionalAction}>
        <button
          type="button"
          data-testid="restart-login"
          className={classes.submitButton}
          disabled={inProgress}
          aria-busy={inProgress}
          onClick={restartLogin}
        >
          <Trans i18nKey="suspended.restart_login" />
        </button>
      </div>
    </>
  );
}
