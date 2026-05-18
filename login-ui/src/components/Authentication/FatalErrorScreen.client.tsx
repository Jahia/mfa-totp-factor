import { useMemo, useState } from "react";
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
}

const suspendedUserErrorCode = "suspended_user";

export default function FatalErrorScreen({ error, onResetFlow }: Readonly<FatalErrorScreenProps>) {
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
    } else {
      return t(
        error.code,
        error.arguments?.reduce(
          (acc, arg) => ({ ...acc, [arg.name]: arg.value }),
          {} as Record<string, string>,
        ),
      );
    }
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
          setMessage(t(key, interpolation));
        }
      })
      .finally(() => setInProgress(false));
  }

  return (
    <>
      {message && <ErrorMessage message={message} />}
      <hr />
      {!inProgress && (
        <div data-testid="additional-action" className={classes.additionalAction}>
          <a data-testid="restart-login" href="#" onClick={restartLogin}>
            <Trans i18nKey="suspended.restart_login" />
          </a>
        </div>
      )}
    </>
  );
}
