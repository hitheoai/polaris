"""Only fixed, non-sensitive diagnostics cross the onboarding boundary."""


class OnboardingProblem(Exception):
    def __init__(self, code: str, message: str, *, exit_code: int = 2) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.exit_code = exit_code
