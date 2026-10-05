"""Static analyzer adapters; importing them never launches a process or loads a model."""

from polaris.review.analyzers.base import AnalysisRuntime, Analyzer, AnalyzerResult

__all__ = ["AnalysisRuntime", "Analyzer", "AnalyzerResult"]
