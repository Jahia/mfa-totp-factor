import { useState } from "react";
import LoginForm from "./LoginForm.client";
import { ApiRootContext } from "../../hooks/ApiRootContext";
import TotpCodeVerificationForm from "./TotpCodeVerificationForm.client";
import EmailCodeVerificationForm from "./EmailCodeVerificationForm.client";
import WebauthnVerificationForm from "./WebauthnVerificationForm.client";
import FactorChooser from "./FactorChooser.client";
import type { Props } from "./types";
import { redirect } from "../../services";
import FatalErrorScreen from "./FatalErrorScreen.client";
import type { MfaError } from "../../services/common";

enum Step {
  LOGIN,
  CHOOSE_FACTOR,
  VERIFY,
  COMPLETE,
  FATAL_ERROR,
}

export default function Authentication({
  apiRoot,
  content,
}: Readonly<{
  apiRoot: string;
  content: Props;
}>) {
  const [step, setStep] = useState<Step>(Step.LOGIN);
  const [fatalError, setFatalError] = useState<MfaError | undefined>(undefined);
  const [availableFactors, setAvailableFactors] = useState<string[]>([]);
  const [activeFactor, setActiveFactor] = useState<string | null>(null);

  const onVerifySuccess = () => {
    setStep(Step.COMPLETE);
    redirect(content.contextPath);
  };

  const onResetFlow = () => {
    setStep(Step.LOGIN);
    setFatalError(undefined);
    setAvailableFactors([]);
    setActiveFactor(null);
  };

  const onLoginSuccess = ({ remainingFactors }: { username: string; remainingFactors: string[] }) => {
    setAvailableFactors(remainingFactors);
    if (remainingFactors.length === 1) {
      // Skip the chooser when there's only one option.
      setActiveFactor(remainingFactors[0]);
      setStep(Step.VERIFY);
    } else {
      setStep(Step.CHOOSE_FACTOR);
    }
  };

  const onFactorPicked = (factor: string) => {
    setActiveFactor(factor);
    setStep(Step.VERIFY);
  };

  const onFatalError = (error: MfaError) => {
    setFatalError(error);
    setStep(Step.FATAL_ERROR);
  };

  // Dispatch to the right verification form. Unknown factor types fall back to a
  // FatalErrorScreen with a clear error code so the user can restart cleanly.
  const renderVerificationForm = () => {
    switch (activeFactor) {
      case "totp":
        return (
          <TotpCodeVerificationForm
            content={content}
            onSuccess={onVerifySuccess}
            onFatalError={onFatalError}
          />
        );
      case "email_code":
        return <EmailCodeVerificationForm onSuccess={onVerifySuccess} onFatalError={onFatalError} />;
      case "webauthn":
        return (
          <WebauthnVerificationForm
            content={content}
            onSuccess={onVerifySuccess}
            onFatalError={onFatalError}
          />
        );
      default:
        return (
          <FatalErrorScreen
            error={{ code: "factor_type_not_supported", arguments: [{ name: "factorType", value: activeFactor ?? "" }] }}
            onResetFlow={onResetFlow}
          />
        );
    }
  };

  return (
    <ApiRootContext value={apiRoot}>
      {step === Step.FATAL_ERROR && fatalError && (
        <FatalErrorScreen error={fatalError} onResetFlow={onResetFlow} />
      )}
      {step === Step.LOGIN && (
        <LoginForm
          content={content}
          onSuccess={onLoginSuccess}
          onAllFactorsCompleted={onVerifySuccess}
          onFatalError={onFatalError}
        />
      )}
      {step === Step.CHOOSE_FACTOR && (
        <FactorChooser factors={availableFactors} onSelect={onFactorPicked} />
      )}
      {step === Step.VERIFY && renderVerificationForm()}
    </ApiRootContext>
  );
}
