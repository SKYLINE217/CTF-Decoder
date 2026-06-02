import sys
import ctf_decoder.decoders # Registers built-ins
from ctf_decoder.registry import registry

def test_decoder(name, encoded, expected):
    decoder = registry.get(name)
    assert decoder is not None, f"Decoder {name} not found"
    result = decoder.decode(encoded)
    assert result == expected, f"Failed {name}: got {result}, expected {expected}"
    print(f"PASS: {name}")

def test_detection():
    from ctf_decoder.detection import DetectionEngine
    engine = DetectionEngine()
    
    cases = [
        (b"SGVsbG8=", "base64"),
        (b"48656c6c6f", "hex"),
        (b"0100100001100101011011000110110001101111", "binary"),
        (b"Hello%20World", "url"),
    ]
    
    for encoded, expected in cases:
        results = engine.detect(encoded)
        assert results, f"Detection failed for {expected}, no results"
        top_codec = results[0][1]
        assert top_codec == expected, f"Detection failed for {expected}, got {top_codec} (full: {results})"
        print(f"DETECT PASS: {expected} -> {results[0]}")

def test_autopilot():
    from ctf_decoder.core.pipeline import PipelineManager
    from ctf_decoder.core.request import DecodeRequest
    
    pipeline = PipelineManager()
    
    # Test Case 1: Base64 -> Rot13 -> Flag
    # Target flag: FLAG{autopilot_works_well}
    # rot13: SYNT{nhgbcvybg_jbexf_jryy}
    # base64: U1lOVHtuaGdiY3Z5YmdfamJleGZfanJ5eX0=
    double_encoded_1 = b"U1lOVHtuaGdiY3Z5YmdfamJleGZfanJ5eX0="
    
    request_1 = DecodeRequest(input_bytes=double_encoded_1)
    result_1 = pipeline.run_autopilot(request_1)
    
    assert result_1.success, f"Autopilot case 1 failed: {result_1.error}"
    assert b"FLAG{autopilot_works_well}" in result_1.final_output, f"Autopilot case 1 returned wrong output: {result_1.final_output}"
    assert len(result_1.steps) == 2, f"Expected 2 steps, got {len(result_1.steps)}"
    assert result_1.steps[0].codec == "base64", f"Expected first step base64, got {result_1.steps[0].codec}"
    assert result_1.steps[1].codec == "rot13", f"Expected second step rot13, got {result_1.steps[1].codec}"
    print("AUTOPILOT PASS 1: base64 -> rot13 -> flag")

    # Test Case 2: Base64 -> XOR-42 -> Flag
    # Target flag: FLAG{heavy_ensemble_works_great}
    # xor-42: lfkmQBOK\SuODYOGHFOu]EXAYuMXOK^W
    # base64: bGZrbVFCT0tcU3VPRFlPR0hGT3VdRVhBWXVNWE9LXlc=
    double_encoded_2 = b"bGZrbVFCT0tcU3VPRFlPR0hGT3VdRVhBWXVNWE9LXlc="
    
    request_2 = DecodeRequest(input_bytes=double_encoded_2)
    result_2 = pipeline.run_autopilot(request_2)
    
    assert result_2.success, f"Autopilot case 2 failed: {result_2.error}"
    assert b"FLAG{heavy_ensemble_works_great}" in result_2.final_output, f"Autopilot case 2 returned wrong output: {result_2.final_output}"
    assert len(result_2.steps) == 2, f"Expected 2 steps, got {len(result_2.steps)}"
    assert result_2.steps[0].codec == "base64", f"Expected first step base64, got {result_2.steps[0].codec}"
    assert result_2.steps[1].codec == "xor", f"Expected second step xor, got {result_2.steps[1].codec}"
    print("AUTOPILOT PASS 2: base64 -> xor -> flag")

def main():
    
    test_decoder("base64", b"SGVsbG8=", b"Hello")
    test_decoder("hex", b"48656c6c6f", b"Hello")
    test_decoder("binary", b"0100100001100101011011000110110001101111", b"Hello")
    test_decoder("url", b"Hello%20World", b"Hello World")
    test_decoder("rot13", b"Uryyb", b"Hello")
    test_decoder("atbash", b"Svool", b"Hello")
    
    print("All basic decoder tests passed.\n")
    test_detection()
    print("All detection tests passed.\n")
    test_autopilot()
    print("All autopilot tests passed.")

if __name__ == "__main__":
    main()
