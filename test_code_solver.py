from ctf_decoder.core.code_solver import CodeSolver

def test_code_solver_static():
    solver = CodeSolver()
    code = (
        "// Embedded flag within comment:\n"
        "// U1lOVHtxcnJjX2ZybmVwdV9uaGdiY3Z5Ymd9\n"
        "char* key = \"U1lOVHtxcnJjX2ZybmVwdV9uaGdiY3Z5Ymd9\";\n"
        "int main() { return 0; }"
    )
    res = solver.solve_code(code, "c", run_dynamically=False)
    assert res["success"] is True
    assert len(res["solves"]) > 0
    assert res["solves"][0]["flag"] == "FLAG{deep_search_autopilot}"
    print("Static code solver test passed!")

def test_code_solver_dynamic():
    solver = CodeSolver()
    code = (
        "import base64\n"
        "val = 'U1lOVHtxcnJjX2ZybmVwdV9uaGdiY3Z5Ymd9'\n"
        "print(val)"
    )
    res = solver.solve_code(code, "python", run_dynamically=True)
    assert res["success"] is True
    assert len(res["solves"]) > 0
    assert res["solves"][0]["flag"] == "FLAG{deep_search_autopilot}"
    print("Dynamic code solver test passed!")

if __name__ == "__main__":
    test_code_solver_static()
    test_code_solver_dynamic()
