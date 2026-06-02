import ctf_decoder.decoders # Ensure codecs are registered
from ctf_decoder.core.solver import ChallengeSolver

def test_challenge_solver():
    solver = ChallengeSolver()
    
    # Target flag: FLAG{deep_search_autopilot}
    # rot13: SYNT{qrrc_frnepu_nhgbcvybg}
    # base64: U1lOVHtxcnJjX2ZybmVwdV9uaGdiY3Z5Ymd9
    challenge_payload = (
        "Hello CTF player!\n"
        "Here is the secret key hidden in base64: U1lOVHtxcnJjX2ZybmVwdV9uaGdiY3Z5Ymd9\n"
        "Good luck solving it!"
    )
    
    solves = solver.solve(challenge_payload)
    
    assert len(solves) > 0, "Expected at least one flag solved"
    
    # Find the correct flag match
    found_correct = False
    for s in solves:
        if b"FLAG{deep_search_autopilot}" in s.result.final_output:
            found_correct = True
            assert s.flag == "FLAG{deep_search_autopilot}"
            assert len(s.result.steps) == 2
            assert s.result.steps[0].codec == "base64"
            assert s.result.steps[1].codec == "rot13"
            break
            
    assert found_correct, "Did not find the correct decoded flag in solves list"
    print("SOLVER PASS: Scanning and recursively solving embedded flag successfully verified!")

if __name__ == "__main__":
    test_challenge_solver()
