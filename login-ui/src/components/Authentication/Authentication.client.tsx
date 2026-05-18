import { useState } from "react";
import LoginForm from "./LoginForm.client";
import { ApiRootContext } from "../../hooks/ApiRootContext";
import TotpCodeVerificationForm from "./TotpCodeVerificationForm.client";
import type { Props } from "./types";
import { redirect } from "../../services";
import FatalErrorScreen from "./FatalErrorScreen.client";
import type { MfaError } from "../../services/common";

enum Step {
  LOGIN,
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

  const handleVerifySuccess = () => {
    setStep(Step.COMPLETE);
    redirect(content.contextPath);
  };

  const handleResetFlow = () => {
    setStep(Step.LOGIN);
    setFatalError(undefined);
  };

  return (
    <ApiRootContext value={apiRoot}>
      {step === Step.FATAL_ERROR && fatalError && (
        <FatalErrorScreen error={fatalError} onResetFlow={handleResetFlow} />
      )}
      {step === Step.LOGIN && (
        <LoginForm
          content={content}
          onSuccess={() => setStep(Step.VERIFY)}
          onAllFactorsCompleted={handleVerifySuccess}
          onFatalError={(error) => {
            setFatalError(error);
            setStep(Step.FATAL_ERROR);
          }}
        />
      )}
      {step === Step.VERIFY && (
        <TotpCodeVerificationForm
          content={content}
          onSuccess={handleVerifySuccess}
          onFatalError={(error) => {
            setFatalError(error);
            setStep(Step.FATAL_ERROR);
          }}
        />
      )}
    </ApiRootContext>
  );
}
