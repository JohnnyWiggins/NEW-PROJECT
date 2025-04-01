import speech_recognition as sr
import queue

speech_queue = queue.Queue()
recognizer = sr.Recognizer()
# Increase the pause threshold to wait longer for pauses
recognizer.pause_threshold = 2.0
# Optionally, remove the phrase_time_limit so it doesn't cut off early
# We'll not specify phrase_time_limit in the listen call

stop_listening_func = None

def callback(recognizer, audio):
    try:
        text = recognizer.recognize_google(audio)
        if text:
            speech_queue.put(text)
    except sr.UnknownValueError:
        pass  # or speech_queue.put("Could not understand the audio.")
    except sr.RequestError:
        speech_queue.put("Speech service is unavailable.")

def start_background_listening():
    global stop_listening_func
    # Create a new Microphone instance each time to avoid context issues
    mic = sr.Microphone()
    if stop_listening_func is None:
        stop_listening_func = recognizer.listen_in_background(mic, callback)

def stop_background_listening():
    global stop_listening_func
    if stop_listening_func is not None:
        stop_listening_func(wait_for_stop=True)
        stop_listening_func = None

def generate_speech():
    while True:
        try:
            text = speech_queue.get(timeout=1)
            yield f"{text}\n\n"
        except queue.Empty:
            yield ""
