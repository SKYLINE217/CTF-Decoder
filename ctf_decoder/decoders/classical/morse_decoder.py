from ctf_decoder.decoders.base import BaseDecoder
import re

MORSE_CODE_DICT = {
    '.-':'A', '-...':'B', '-.-.':'C', '-..':'D', '.':'E',
    '..-.':'F', '--.':'G', '....':'H', '..':'I', '.---':'J',
    '-.-':'K', '.-..':'L', '--':'M', '-.':'N', '---':'O',
    '.--.':'P', '--.-':'Q', '.-.':'R', '...':'S', '-':'T',
    '..-':'U', '...-':'V', '.--':'W', '-..-':'X', '-.--':'Y',
    '--..':'Z', '.----':'1', '..---':'2', '...--':'3',
    '....-':'4', '.....':'5', '-....':'6', '--...':'7',
    '---..':'8', '----.':'9', '-----':'0', '--..--':', ',
    '.-.-.-':'.', '..--..':'?', '-..-.':'/', '-.--.':'(',
    '-.--.-':')'
}

class MorseDecoder(BaseDecoder):
    name = "morse"
    aliases = ["morsecode"]
    description = "Decodes standard Morse code (dots and dashes)."

    def can_decode(self, data: bytes) -> float:
        try:
            s = data.decode("ascii").strip()
        except UnicodeDecodeError:
            return 0.0
        
        if not s:
            return 0.0
            
        # Check if it consists mostly of . - and spaces
        if not re.match(r'^[.\-\s]+$', s):
            return 0.0
            
        return 0.9

    def decode(self, data: bytes) -> bytes:
        try:
            s = data.decode("ascii").strip()
        except UnicodeDecodeError:
            raise ValueError("Morse code must be ASCII")
            
        if not re.match(r'^[.\-\s]+$', s):
            raise ValueError("Invalid characters in Morse code")
            
        words = s.split('   ')
        decoded = []
        for word in words:
            chars = word.split(' ')
            decoded_word = []
            for char in chars:
                if char in MORSE_CODE_DICT:
                    decoded_word.append(MORSE_CODE_DICT[char])
                elif char:
                    decoded_word.append('?') # Unknown char
            decoded.append(''.join(decoded_word))
            
        return ' '.join(decoded).encode('utf-8')
