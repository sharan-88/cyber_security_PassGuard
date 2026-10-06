"""Static word lists used by the analyzer.

Everything lives in memory so the application works fully offline.
"""

# ~130 of the most frequently leaked passwords (lower-case).
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "123456789", "1234567890", "12345", "1234567",
    "111111", "000000", "123123", "654321", "666666", "121212", "112233", "123321",
    "qwerty", "qwerty123", "qwertyuiop", "qwe123", "asdfgh", "asdfghjkl", "zxcvbnm",
    "1q2w3e4r", "1q2w3e", "1qaz2wsx", "q1w2e3r4", "abc123", "abcd1234", "abcdef",
    "password1", "pass1234", "pass123", "passpass",
    "admin", "admin123", "administrator", "root", "toor", "user", "guest", "test",
    "test123", "login", "welcome", "welcome1", "letmein", "iloveyou", "iloveu",
    "monkey", "dragon", "master", "shadow", "sunshine", "princess", "football",
    "baseball", "superman", "batman", "trustno1", "freedom", "whatever", "starwars",
    "hello", "hello123", "charlie", "donald", "michael", "jordan", "jennifer",
    "hunter", "ranger", "buster", "soccer", "hockey", "killer", "george", "harley",
    "ashley", "bailey", "thomas", "tigger", "robert", "daniel", "andrew", "joshua",
    "matthew", "summer", "winter", "secret", "computer", "internet", "google",
    "facebook", "default", "changeme", "qazwsx", "zaq12wsx", "access", "flower",
    "cheese", "pepper", "ginger", "orange", "banana", "cookie", "chocolate",
    "mustang", "696969", "lovely", "samsung", "india123", "india", "krishna",
    "ganesh", "shiva", "ramesh", "sachin", "cricket", "bangalore", "mysore",
    "mypassword", "myspace1", "nothing", "zxcvbn", "1111", "0000", "1234",
}

# Common base words people build passwords around.
DICTIONARY_WORDS = {
    "password", "passw", "welcome", "login", "admin", "user", "letmein", "secret",
    "master", "monkey", "dragon", "shadow", "sunshine", "princess", "football",
    "baseball", "superman", "batman", "freedom", "hello", "love", "iloveyou",
    "summer", "winter", "spring", "autumn", "monday", "friday", "sunday", "india",
    "college", "student", "teacher", "school", "computer", "internet", "google",
    "apple", "banana", "orange", "cookie", "chocolate", "flower", "ginger",
    "tiger", "lion", "cricket", "soccer", "hockey", "bangalore", "mysore",
    "karnataka", "krishna", "ganesh", "shiva", "family", "friend", "happy",
    "lucky", "angel", "devil", "killer", "hunter", "ranger", "mustang", "harley",
    "charlie", "michael", "jordan", "daniel", "robert", "thomas", "ashley",
    "jennifer", "qwerty", "asdf", "zxcv", "test", "guest", "root", "default",
    "access", "money", "bank", "pass", "word", "name", "king", "queen", "star",
    "moon", "sun", "correct", "horse", "battery", "staple", "blue", "red", "black", "white", "green", "pink",
}

KEYBOARD_ROWS = [
    "qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890",
    "!@#$%^&*()",
]

LEET_MAP = {
    "@": "a", "4": "a", "8": "b", "(": "c", "3": "e", "6": "g", "9": "g",
    "#": "h", "1": "i", "!": "i", "|": "l", "0": "o", "$": "s", "5": "s",
    "7": "t", "+": "t", "2": "z",
}
