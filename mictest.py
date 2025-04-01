import speech_recognition as sr


def test_microphone():
    recognizer = sr.Recognizer()
    mic = sr.Microphone()

    # Print the list of available microphones
    print(sr.Microphone.list_microphone_names())

    with mic as source:
        print("Adjusting for ambient noise... Please speak.")
        recognizer.adjust_for_ambient_noise(source)
        audio = recognizer.listen(source)

    try:
        print("Recognizing speech...")
        text = recognizer.recognize_google(audio)
        print("You said: " + text)
    except sr.UnknownValueError:
        print("Sorry, I could not understand the audio.")
    except sr.RequestError:
        print("Sorry, the speech service is unavailable.")


test_microphone()
