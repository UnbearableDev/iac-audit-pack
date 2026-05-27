FROM apify/actor-python:3.14
USER myuser
COPY --chown=myuser:myuser requirements.txt ./
RUN pip install -r requirements.txt
COPY --chown=myuser:myuser . ./
RUN python -m compileall -q iac_audit_pack/
CMD ["python", "-m", "iac_audit_pack"]
