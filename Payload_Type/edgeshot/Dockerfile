# Base Python image provided by Mythic. It already ships mythic_container at
# the version matching the server.
FROM itsafeaturemythic/mythic_python_base:latest

# Extra Python dependencies (not present in the base Mythic image):
#   cryptography — RSA key generation for the stomp/GAP Secure-Preferences
#                  "random ID" build path.
#   pillow       — resize a custom uploaded extension icon to 16/48/128.
RUN pip install --no-cache-dir cryptography pillow

# Copy every file of the edgeshot folder into the container.
WORKDIR /Mythic/
COPY . .

# Command run when the container starts.
CMD ["python3", "main.py"]
