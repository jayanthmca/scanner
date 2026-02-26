from abc import ABC, abstractmethod

class BaseModule:
    def collect(self, context=None):
        """Optional context argument for URLs / targets"""
        return []

    def scan(self, context=None):
        """Optional context argument"""
        return []

    def analyze(self, data, context=None):
        """Optional context for analysis"""
        return []