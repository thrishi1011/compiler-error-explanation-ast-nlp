class CompilerError:
    def __init__(self,file,line,column,error_type,message,raw,security_risk=None,risk_reason=None,security_findings=None):
        self.file=file
        self.line=line
        self.column=column
        self.error_type=error_type.lower()
        self.message=message
        self.raw=raw

        self.explanation=None
        self.suggestion =None
        self.context=None
        self.category=None
        self.confidence=0.0
        self.security_risk=security_risk
        self.risk_reason=risk_reason
        self.security_findings=security_findings or []

    def to_dict(self):
        findings=[]
        for finding in getattr(self, "security_findings", []) or []:
            if hasattr(finding, "to_dict"):
                findings.append(finding.to_dict())
            elif isinstance(finding, dict):
                findings.append(finding)
            else:
                findings.append(str(finding))

        return {
            "file":self.file,
            "line":self.line,
            "column":self.column,
            "type":self.error_type,
            "message":self.message,
            "explanation":self.explanation,
            "suggestion":self.suggestion,
            "context":self.context,
            "category":self.category,
            "confidence":self.confidence,
            "security_risk":self.security_risk,
            "risk_reason":self.risk_reason,
            "security_findings":findings,
        }
    
    def __str__(self):
        parts=[]
        location=""
        if self.file:
            location+=self.file
        if self.line:
            location+=f":{self.line}"
        if self.column:
            location+=f":{self.column}"
        if location:
            parts.append(location+" ")
        #file:line:column

        parts.append(f"{self.error_type.upper()}:{self.message}")

        if self.explanation:
            parts.append(f"\nExplanation: {self.explanation}")
        if self.suggestion:
            parts.append(f"\nSuggestion: {self.suggestion}")
        if self.category:
            parts.append(
                f"\nCategory: {self.category} (confidence: {self.confidence:.2f})"
            )

        if self.context:
            parts.append("\nContext:")
            start=self.context["start_line"]

            for i,line in enumerate(self.context["lines"],start=start):
                marker="→" if i==self.line else " "
                parts.append(f"\n{i:4} {marker} {line.rstrip()}")

                if i == self.line and self.column:
                    parts.append("\n" + " " * (self.column + 6) + "^")

        return "".join(parts)
