import re
from typing import Dict, Any, Optional
from error_classifier import get_default_classifier
from error_normalizer import normalize_error
from common_errors import COMMON_ERRORS
from security_analyzer import analyze
from second_opinion import get_second_opinion, format_second_opinion

EXPLANATIONS = {
    "syntax_error": {
        "what": "The compiler found an unexpected token or character in your code.",
        "why": "C++ has strict syntax rules. A missing semicolon, bracket, or parenthesis causes the parser to lose track of where one statement ends and another begins.",
        "how": "Check the line reported and the line just before it. Look for a missing ';', unmatched '(' or '{', or a stray character.",
        "suggestion": "Fix the syntax error near the reported location."
    },
    "name_resolution": {
        "what": "The compiler encountered an identifier that has not been declared.",
        "why": "In C++, every variable, function, or class must be declared before it is used. It may also be in a different scope or namespace.",
        "how": "Declare the variable before using it, check your spelling, or add the missing #include or 'using namespace std;'.",
        "suggestion": "Declare the identifier before use or add the missing #include."
    },
    "type_error": {
        "what": "A value of one type is being used where an incompatible type is expected.",
        "why": "C++ is strongly typed. Operations between incompatible types are not allowed without an explicit cast.",
        "how": "Check the types of the values involved. Add an explicit cast, change the variable type, or use the correct operator.",
        "suggestion": "Ensure both operands are compatible types or add an explicit cast."
    },
    "missing_include": {
        "what": "A required header file could not be found.",
        "why": "The function or class you are using is defined in a header file that has not been included in your source file.",
        "how": "Add the appropriate #include at the top of your file. For standard library features use angle brackets e.g. #include <iostream>.",
        "suggestion": "Add the missing #include directive at the top of your file."
    },
    "linker_error": {
        "what": "The linker could not find the definition of a function or variable.",
        "why": "The compiler found a declaration but no matching definition was compiled into the project.",
        "how": "Make sure the .cpp file containing the definition is being compiled. Check for typos in the function name or missing library flags.",
        "suggestion": "Ensure the function is defined and all source files are being compiled."
    },
    "redefinition": {
        "what": "The same identifier is defined more than once.",
        "why": "C++ does not allow two definitions of the same variable or function in the same scope.",
        "how": "Remove the duplicate definition. If it is coming from a header file, add #pragma once or include guards.",
        "suggestion": "Remove the duplicate definition or add include guards to your header."
    },
    "access_error": {
        "what": "A private or protected member is being accessed from outside its class.",
        "why": "C++ enforces access control. Private members can only be accessed from within the class itself.",
        "how": "Use a public getter/setter method, declare the accessing code as a friend, or change the member's access level.",
        "suggestion": "Use a public method to access the member or change its access level."
    },
    "return_type_error": {
        "what": "A function is missing a return statement or returns the wrong type.",
        "why": "In C++, non-void functions must return a value that matches their declared return type. main() must always return int.",
        "how": "Add a return statement with the correct type. For main(), use 'return 0;' at the end.",
        "suggestion": "Add a return statement matching the function's declared return type."
    },
    "other": {
        "what": "The compiler reported an issue that does not fit a standard category.",
        "why": "This may be a warning treated as an error, a platform-specific issue, or an uncommon language rule violation.",
        "how": "Read the full compiler message carefully and check the indicated line for the root cause.",
        "suggestion": "Read the compiler message carefully and correct the highlighted code."
    }
}

def lookup_common_error(message: str) -> Optional[Dict[str, Any]]:
    """
    Check if the error message matches any of the pre-defined common errors.
    Uses substring matching to handle variations while maintaining specificity.
    """
    lowered_msg = message.lower()
    for common in COMMON_ERRORS:
        # Check if the common error message (or a major part of it) is in the actual message
        # We strip surrounding quotes if they exist in the template to match more flexibly
        template_msg = common["message"].lower().strip("'\"")
        if template_msg in lowered_msg:
            return common
    return None

def format_error(what: str, why: str, how: str) -> str:
    return (
        f"What happened:\n"
        f" {what}\n\n"
        f"Why it happened:\n"
        f" {why}\n\n"
        f"How to fix it:\n"
        f" {how}"
    )

def explain_category(category: str, message: str) -> Optional[Dict[str, str]]:
    if category not in EXPLANATIONS:
        return None
    
    template = EXPLANATIONS[category]
    
    # Use normalizer to get a specific readable sentence for the 'what' part
    _, specific_what = normalize_error(message)
    
    explanation = format_error(
        what=specific_what,
        why=template["why"],
        how=template["how"]
    )
    
    return {
        "explanation": explanation,
        "suggestion": template["suggestion"]
    }

SECURITY_RULES = [
    {
        "pattern": r"unused variable|variable .+ set but not used",
        "risk": "Low",
        "reason": "Unused variables can indicate dead code, abandoned checks, or incomplete security logic."
    },
    {
        "pattern": r"may be used uninitialized",
        "risk": "High",
        "reason": "Uninitialized variables may cause undefined behavior or memory corruption."
    },
    {
        "pattern": r"division by zero",
        "risk": "High",
        "reason": "Division by zero can crash the program or cause undefined behavior."
    },
    {
        "pattern": r"invalid conversion",
        "risk": "Medium",
        "reason": "Incorrect type conversion may lead to memory or logic errors."
    },
    {
        "pattern": r"assignment of read-only location",
        "risk": "Medium",
        "reason": "Modifying const-qualified data may indicate unsafe design."
    },
    {
        "pattern": r"undefined reference",
        "risk": "Low",
        "reason": "Linker errors typically do not introduce runtime vulnerabilities."
    }
]

def analyze_security_risk(error):
    if not error or not error.message:
        return "None", None

    for rule in SECURITY_RULES:
        if re.search(rule["pattern"], error.message, re.IGNORECASE):
            return rule["risk"], rule["reason"]
    return "Low", "No immediate security risk detected."

def explain_error(error) -> Dict[str, Any]:
    if not error or not error.message:
        return {
            "explanation": "No error message provided.",
            "suggestion": "Check the compilation command and input files.",
            "category": "Unknown",
            "confidence": 0.0
        }

    # 1. First, check specific C++ compiler diagnostic patterns
    lowered_msg = error.message.lower()

    if "assignment used as truth value" in lowered_msg or "suggest parentheses around assignment" in lowered_msg or "parentheses around assignment" in lowered_msg:
        return {
            "explanation": format_error(
                what="An assignment operator ('=') was used inside a condition expression instead of an equality comparison ('==').",
                why="In C++, '=' assigns a value to a variable, while '==' tests if two values are equal. Writing 'if (x = 50)' assigns 50 to x and evaluates to 50 (which is non-zero/true), rather than checking if x equals 50.",
                how="Change '=' to '==' for comparison: 'if (x == 50)'. If assignment was genuinely intended, wrap it in extra parentheses: 'if ((x = 50))'."
            ),
            "suggestion": "if (x == 50) { // use '==' for comparison",
            "category": "syntax_error",
            "confidence": 1.0
        }

    if "unused variable" in lowered_msg or "unused parameter" in lowered_msg or "set but not used" in lowered_msg:
        v_match = re.search(r"['‘]([a-zA-Z_]\w*)['’]", error.message)
        v_name = v_match.group(1) if v_match else "var"
        return {
            "explanation": format_error(
                what=f"The variable '{v_name}' was declared and initialized but is never referenced or read anywhere in the function.",
                why="C++ compilers warn about unused variables to prevent dead code, leftover refactoring artifacts, and potential logic bugs.",
                how=f"Remove the unused variable '{v_name}', or suppress the warning with '(void){v_name};' if you plan to use it later."
            ),
            "suggestion": f"(void){v_name}; // or remove unused variable",
            "category": "unused_variable",
            "confidence": 1.0
        }

    if "division by zero" in lowered_msg or "divide by zero" in lowered_msg:
        return {
            "explanation": format_error(
                what="A division or modulo operation is performed with a divisor of zero.",
                why="Division by zero is undefined behavior in C++ and causes an immediate runtime crash (SIGFPE) or hardware trap.",
                how="Verify that the divisor is non-zero before dividing: e.g. 'if (b != 0) return a / b; else return 0;'."
            ),
            "suggestion": "if (b != 0) return a / b; else return 0;",
            "category": "other",
            "confidence": 1.0
        }

    if "array subscript is not an integer" in lowered_msg or "subscripted value is not an array" in lowered_msg:
        return {
            "explanation": format_error(
                what="The array subscript expression must evaluate to an integral type, but a non-integer (such as float or double) was provided.",
                why="C++ array indexing requires an integer offset to compute memory addresses. Floating-point numbers cannot be used as array indices.",
                how="Cast or round the index to an integer: e.g. 'arr[static_cast<int>(index)]', or use an integer variable."
            ),
            "suggestion": "arr[static_cast<int>(index)];",
            "category": "type_error",
            "confidence": 1.0
        }

    if "break statement not within loop or switch" in lowered_msg:
        return {
            "explanation": format_error(
                what="A 'break' statement was encountered outside of any loop or switch construct.",
                why="In C++, 'break' is only valid inside loop bodies ('for', 'while', 'do-while') or 'switch' statements to terminate execution.",
                how="Remove the 'break' statement, or wrap the enclosing logic in a loop or switch block."
            ),
            "suggestion": "Remove 'break;' or place inside an enclosing loop or switch block.",
            "category": "syntax_error",
            "confidence": 1.0
        }

    if "continue statement not within a loop" in lowered_msg:
        return {
            "explanation": format_error(
                what="A 'continue' statement was encountered outside of a loop.",
                why="In C++, 'continue' is only valid inside loop bodies ('for', 'while', 'do-while') to jump to the next iteration.",
                how="Remove the 'continue' statement, or wrap the logic in an enclosing loop."
            ),
            "suggestion": "Remove 'continue;' or place inside an enclosing loop.",
            "category": "syntax_error",
            "confidence": 1.0
        }

    if "invalid use of void expression" in lowered_msg:
        return {
            "explanation": format_error(
                what="A function returning 'void' is being evaluated as a value or assigned to a variable.",
                why="In C++, 'void' denotes no value. You cannot assign the result of a void function or use it in an expression.",
                how="Call the void function on its own line: e.g. 'foo();' without assigning its result."
            ),
            "suggestion": "foo(); // call void function as standalone statement",
            "category": "type_error",
            "confidence": 1.0
        }

    if "invalid cast from type" in lowered_msg or "static_cast" in lowered_msg and "cannot convert" in lowered_msg:
        return {
            "explanation": format_error(
                what="An invalid cast was attempted between incompatible types.",
                why="C++ static_cast does not allow casting arbitrary unrelated types without an explicit conversion operator or pointer relationship.",
                how="Check the source and target types. If converting an integer to a pointer, take the address of the variable: '&x' or use reinterpret_cast."
            ),
            "suggestion": "int* p = &x; // use address-of '&' instead of invalid cast",
            "category": "type_error",
            "confidence": 1.0
        }

    if "invalid operands of types" in lowered_msg:
        return {
            "explanation": format_error(
                what="The binary operator cannot be applied to operands of these types.",
                why="C++ does not define an operator for this combination of types (e.g. adding an integer to a string literal).",
                how="Convert the operands to compatible types (e.g. use 'to_string(num) + str')."
            ),
            "suggestion": "to_string(num) + str",
            "category": "type_error",
            "confidence": 1.0
        }

    if "assignment of read-only" in lowered_msg:
        return {
            "explanation": format_error(
                what="Attempted to modify a variable declared with 'const' (read-only).",
                why="The 'const' qualifier prohibits modifying the value after initialization.",
                how="Remove 'const' if the variable needs to be mutable, or avoid reassigning to it."
            ),
            "suggestion": "int x = 10; // remove const to allow assignment",
            "category": "access_error",
            "confidence": 1.0
        }

    if "sizeof' to a function" in lowered_msg or "invalid application of 'sizeof' to a function" in lowered_msg:
        return {
            "explanation": format_error(
                what="Invalid application of 'sizeof' to a function type.",
                why="A function type itself has no object size in C++. You can only take the size of an object or data type.",
                how="If measuring the return value, invoke the function: 'sizeof(foo(args))', or measure a data type: 'sizeof(int)'."
            ),
            "suggestion": "sizeof(foo(42)); // measure size of returned value",
            "category": "type_error",
            "confidence": 1.0
        }

    if "no matching function for call to" in lowered_msg or "no matching constructor" in lowered_msg:
        return {
            "explanation": format_error(
                what="The compiler could not find any function overload or constructor matching the provided arguments.",
                why="The argument types or count do not match any available function declaration in scope.",
                how="Check the parameter types expected by the function and pass the matching arguments."
            ),
            "suggestion": "Check function definition and pass expected argument types.",
            "category": "type_error",
            "confidence": 1.0
        }

    if "redefinition of" in lowered_msg or "multiple definition of" in lowered_msg:
        return {
            "explanation": format_error(
                what="The symbol has already been defined in this scope or translation unit.",
                why="C++ One Definition Rule (ODR) prohibits multiple definitions of the same variable or function.",
                how="Remove the duplicate definition, rename one of them, or use include guards."
            ),
            "suggestion": "Remove or rename the duplicate definition.",
            "category": "redefinition",
            "confidence": 1.0
        }

    if "no return statement in function returning non-void" in lowered_msg or "control reaches end of non-void function" in lowered_msg:
        return {
            "explanation": format_error(
                what="A function declared with a non-void return type does not return a value on all code paths.",
                why="Reaching the end of a non-void function without a return statement causes undefined behavior in C++.",
                how="Add a 'return <value>;' statement before the end of the function body, or change the return type to 'void'."
            ),
            "suggestion": "return result; // return value matching declared return type",
            "category": "return_type_error",
            "confidence": 1.0
        }

    # 2. Check the Common Errors Glossary
    common = lookup_common_error(error.message)
    if common:
        return {
            "explanation": format_error(
                what=common["explanation"],
                why=EXPLANATIONS.get(common["category"], EXPLANATIONS["other"])["why"],
                how=EXPLANATIONS.get(common["category"], EXPLANATIONS["other"])["how"]
            ),
            "suggestion": common["suggestion"],
            "category": common["category"],
            "confidence": common["confidence"]
        }

    # 2. Fallback to ML-based classification and templated explanation
    classifier = get_default_classifier()
    ast_node = getattr(error, "ast_node", "")
    category, confidence = classifier.predict(error.message, ast_node=ast_node)

    # Regex fallbacks if ML confidence is low
    if confidence < 0.45:
        if re.search(r"expected\s+';", error.message, re.IGNORECASE):
            category = "syntax_error"
            confidence = 0.95
        elif re.search(r"was not declared in this scope", error.message, re.IGNORECASE):
            category = "name_resolution"
            confidence = 0.95
        elif re.search(r"cannot convert", error.message, re.IGNORECASE):
            category = "type_error"
            confidence = 0.9

    template_category = category 
    
    fine = explain_category(template_category, error.message)
    
    if not fine:
        template_category = "other"
        fine = explain_category(template_category, error.message)

    explanation = fine["explanation"]
    suggestion = fine["suggestion"]
    
    node = getattr(error, "ast_node", None)
    if node:
        explanation += f"\n\nThis error occurred inside a {node} statement."
        confidence = min(1.0, confidence + 0.05)
    
    return {
        "explanation": explanation,
        "suggestion": suggestion,
        "category": template_category,
        "confidence": confidence,
    }

def enrich_error(error: 'CompilerError') -> None:
    if not error:
        return
    result = explain_error(error)

    error.explanation = result["explanation"]
    error.suggestion = result["suggestion"]
    error.category = result["category"]
    error.confidence = result["confidence"]

    risk, reason = analyze_security_risk(error)
    error.security_risk = risk
    error.risk_reason = reason

    if error.file and error.line and not error.context:
        from error_parser import get_source_context
        error.context = get_source_context(error.file, error.line)

    error.security_findings = []
    if error.file:
        try:
            findings = analyze(error.file, [error])
            error.security_findings = [
                finding for finding in findings
                if finding.source == "compiler_diagnostic" or finding.line == error.line
            ]
        except Exception:
            error.security_findings = []

    # ── Feature 2: Second opinion ────────────────────────────────────────────
    # Run both the regex classifier and the ML classifier independently and
    # compare their predictions.  The result is stored on the error object so
    # the GUI and CLI can display it alongside the main explanation.
    try:
        ast_ctx = getattr(error, "ast_node", "") or ""
        opinion = get_second_opinion(error.message, ast_node=ast_ctx)
        error.second_opinion = opinion
        error.second_opinion_text = format_second_opinion(opinion)
    except Exception:
        error.second_opinion = None
        error.second_opinion_text = ""

