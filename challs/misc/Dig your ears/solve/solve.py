import wave
import numpy as np

# Open the .wav file
with wave.open("sample.wav", "rb") as wave_file:

    # Get the sample rate and number of channels
    sample_rate = wave_file.getframerate()
    num_channels = wave_file.getnchannels()

    # Read the entire audio file into a numpy array
    audio_data = np.frombuffer(wave_file.readframes(-1), dtype=np.int16)

    # Split the audio data into 10 millisecond chunks
    chunk_size = int(0.01 * sample_rate)
    audio_chunks = [audio_data[i:i+chunk_size*num_channels] for i in range(0, len(audio_data), chunk_size*num_channels)]

    # Create a list to store the bits
    bits = []

    # Loop through each audio chunk
    for chunk in audio_chunks:

        # Apply a window function to the audio chunk
        windowed_chunk = chunk * np.hanning(len(chunk))

        # Perform the FFT on the windowed audio chunk
        fft_data = np.fft.rfft(windowed_chunk)

        # Get the dominant frequency
        freqs = np.fft.rfftfreq(len(chunk), d=1/sample_rate)
        dominant_freq = freqs[np.argmax(np.abs(fft_data))]

        # Determine the bit based on the dominant frequency
        if dominant_freq == 1200:
            bits.append(0)
        elif dominant_freq == 2400:
            bits.append(1)

    # Convert the bits into ASCII characters to get the flag
    binary_str = "".join([str(bit) for bit in bits])
    flag = "".join([chr(int(binary_str[i:i+8], 2)) for i in range(0, len(binary_str), 8)])
    print(binary_str)
    print(flag)