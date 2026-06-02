import re
import subprocess
import tempfile
import os
import sys
from typing import List, Dict, Any
from pathlib import Path
from ctf_decoder.core.solver import ChallengeSolver, ChallengeSolve

class CodeSolver:
    """
    Parses and solves flags from code scripts (Python, C, Java)
    using static analysis (literal extraction) or dynamic execution.
    """
    def __init__(self):
        self.challenge_solver = ChallengeSolver()

    def extract_literals(self, code: str) -> List[str]:
        """Extracts unique string and hex literals from C, Java, or Python code."""
        extracted = []
        
        # 1. Double quoted strings: "..."
        for m in re.finditer(r'"((?:[^"\\]|\\.)*)"', code):
            val = m.group(1)
            # Unescape common sequences
            try:
                # Use codecs escape to unescape hex/octal sequences
                val = bytes(val, "utf-8").decode("unicode_escape")
            except Exception:
                pass
            if len(val.strip()) >= 6:
                extracted.append(val.strip())

        # 2. Single quoted strings: '...'
        for m in re.finditer(r"'((?:[^'\\]|\\.)*)'", code):
            val = m.group(1)
            try:
                val = bytes(val, "utf-8").decode("unicode_escape")
            except Exception:
                pass
            if len(val.strip()) >= 6:
                extracted.append(val.strip())

        # 3. Hex constants e.g. 0x4142...
        for m in re.finditer(r'\b0x([a-fA-F0-9]+)\b', code):
            hex_str = m.group(1)
            if len(hex_str) >= 8:
                try:
                    decoded = bytes.fromhex(hex_str).decode("utf-8", errors="ignore")
                    if len(decoded.strip()) >= 6:
                        extracted.append(decoded.strip())
                except Exception:
                    pass
                extracted.append(m.group(0))

        # 4. Comments (often hide flags or encodings)
        # Single-line: // ... or # ...
        for m in re.finditer(r'(?://|#)\s*(.+)$', code, re.MULTILINE):
            val = m.group(1).strip()
            if len(val) >= 6:
                extracted.append(val)
                
        # Multi-line comments: /* ... */
        for m in re.finditer(r'/\*([\s\S]*?)\*/', code):
            val = m.group(1).strip()
            if len(val) >= 6:
                extracted.append(val)

        # Deduplicate and filter out obvious code keyword false positives
        ignored_keywords = {"import", "public", "class", "static", "void", "return", "include", "define"}
        clean_extracted = []
        for x in extracted:
            if x not in clean_extracted and x not in ignored_keywords:
                clean_extracted.append(x)

        return clean_extracted

    def execute_script(self, code: str, language: str) -> Dict[str, Any]:
        """Runs the script safely in a subprocess with a timeout and captures stdout/stderr."""
        language = language.lower()
        logs = ""
        output_text = ""
        success = False

        # Create temporary workspace directory
        temp_dir = Path(tempfile.gettempdir()) / "ctf_decoder_exec"
        temp_dir.mkdir(exist_ok=True)

        if language == "python":
            script_path = temp_dir / "temp_exec.py"
            script_path.write_text(code, encoding="utf-8")
            try:
                proc = subprocess.run(
                    [sys.executable, str(script_path)],
                    capture_output=True,
                    text=True,
                    timeout=5.0
                )
                logs = f"Exit code: {proc.returncode}\n--- Stdout ---\n{proc.stdout}\n--- Stderr ---\n{proc.stderr}"
                output_text = proc.stdout
                success = (proc.returncode == 0)
            except subprocess.TimeoutExpired:
                logs = "Error: Python execution timed out after 5.0 seconds."
            except Exception as e:
                logs = f"Error executing Python script: {e}"
            finally:
                if script_path.exists():
                    try: os.remove(script_path)
                    except: pass

        elif language == "c":
            source_path = temp_dir / "temp_exec.c"
            exec_path = temp_dir / "temp_exec.exe" if sys.platform == "win32" else temp_dir / "temp_exec"
            source_path.write_text(code, encoding="utf-8")
            
            # Try to compile with gcc or clang
            compiler = "gcc"
            try:
                subprocess.run(["gcc", "--version"], capture_output=True)
            except FileNotFoundError:
                try:
                    subprocess.run(["clang", "--version"], capture_output=True)
                    compiler = "clang"
                except FileNotFoundError:
                    compiler = None

            if not compiler:
                logs = "Error: No C compiler (gcc or clang) found in path. Falling back to static extraction."
                return {"success": False, "logs": logs, "stdout": ""}

            try:
                # Compile
                comp_proc = subprocess.run(
                    [compiler, str(source_path), "-o", str(exec_path)],
                    capture_output=True,
                    text=True,
                    timeout=5.0
                )
                if comp_proc.returncode != 0:
                    logs = f"Compilation failed:\n{comp_proc.stderr}"
                    return {"success": False, "logs": logs, "stdout": ""}
                
                # Execute
                exec_proc = subprocess.run(
                    [str(exec_path)],
                    capture_output=True,
                    text=True,
                    timeout=5.0
                )
                logs = f"Compilation Succeeded.\nExit code: {exec_proc.returncode}\n--- Stdout ---\n{exec_proc.stdout}\n--- Stderr ---\n{exec_proc.stderr}"
                output_text = exec_proc.stdout
                success = (exec_proc.returncode == 0)
            except subprocess.TimeoutExpired:
                logs = "Error: C compilation/execution timed out."
            except Exception as e:
                logs = f"Error building/running C program: {e}"
            finally:
                if source_path.exists():
                    try: os.remove(source_path)
                    except: pass
                if exec_path.exists():
                    try: os.remove(exec_path)
                    except: pass

        elif language == "java":
            # Extract class name if present, otherwise default to TempExec
            class_match = re.search(r'class\s+([A-Za-z0-9_]+)', code)
            class_name = class_match.group(1) if class_match else "TempExec"
            
            # If no class name was found and default class is injected, wrap it if main exists
            if not class_match and "public static void main" in code:
                code = f"public class TempExec {{\n{code}\n}}"
                class_name = "TempExec"

            source_path = temp_dir / f"{class_name}.java"
            source_path.write_text(code, encoding="utf-8")

            # Check for javac
            try:
                subprocess.run(["javac", "-version"], capture_output=True)
            except FileNotFoundError:
                logs = "Error: Java compiler (javac) not found in path. Falling back to static extraction."
                return {"success": False, "logs": logs, "stdout": ""}

            try:
                # Compile
                comp_proc = subprocess.run(
                    ["javac", str(source_path)],
                    capture_output=True,
                    text=True,
                    timeout=5.0
                )
                if comp_proc.returncode != 0:
                    logs = f"Java compilation failed:\n{comp_proc.stderr}"
                    return {"success": False, "logs": logs, "stdout": ""}

                # Run
                exec_proc = subprocess.run(
                    ["java", "-cp", str(temp_dir), class_name],
                    capture_output=True,
                    text=True,
                    timeout=5.0
                )
                logs = f"Java Compilation Succeeded.\nExit code: {exec_proc.returncode}\n--- Stdout ---\n{exec_proc.stdout}\n--- Stderr ---\n{exec_proc.stderr}"
                output_text = exec_proc.stdout
                success = (exec_proc.returncode == 0)
            except subprocess.TimeoutExpired:
                logs = "Error: Java compilation/execution timed out."
            except Exception as e:
                logs = f"Error compiling/running Java program: {e}"
            finally:
                if source_path.exists():
                    try: os.remove(source_path)
                    except: pass
                class_file = temp_dir / f"{class_name}.class"
                if class_file.exists():
                    try: os.remove(class_file)
                    except: pass
        else:
            logs = f"Error: Unsupported language: {language}"

        return {"success": success, "logs": logs, "stdout": output_text}

    def solve_code(self, code: str, language: str, run_dynamically: bool = False, flag_pattern: str = None) -> Dict[str, Any]:
        """Orchestrates solving a pasted code snippet."""
        extracted_literals = []
        logs = ""
        solves: List[ChallengeSolve] = []
        extra_patterns = [flag_pattern] if flag_pattern else None

        if run_dynamically:
            exec_res = self.execute_script(code, language)
            logs = exec_res["logs"]
            if exec_res["success"] and exec_res["stdout"].strip():
                # Solve the stdout output
                solves = self.challenge_solver.solve(exec_res["stdout"], extra_flag_patterns=extra_patterns)
            else:
                # Fallback to static extraction if dynamic execution fails
                extracted_literals = self.extract_literals(code)
                for lit in extracted_literals:
                    cand_solves = self.challenge_solver.solve(lit, extra_flag_patterns=extra_patterns)
                    solves.extend(cand_solves)
        else:
            extracted_literals = self.extract_literals(code)
            for lit in extracted_literals:
                cand_solves = self.challenge_solver.solve(lit, extra_flag_patterns=extra_patterns)
                solves.extend(cand_solves)

        # Format return structure
        formatted_solves = []
        for s in solves:
            steps = [{"codec": step.codec, "output_str": step.output.decode("utf-8", errors="replace")} for step in s.result.steps]
            formatted_solves.append({
                "candidate": {
                    "match": s.candidate.raw_match,
                    "type": s.candidate.match_type,
                    "start": s.candidate.start,
                    "end": s.candidate.end
                },
                "steps": steps,
                "flag": s.flag
            })

        return {
            "success": len(formatted_solves) > 0,
            "logs": logs,
            "extracted_literals": extracted_literals,
            "solves": formatted_solves
        }
