import re

def analyze_log(filepath):

    threats = []

    try:

        with open(filepath, "r", encoding="utf-8") as file:

            lines = file.readlines()

            for line in lines:

                if "failed" in line.lower():

                    threats.append(
                        f"Failed Login Attempt -> {line.strip()}"
                    )

                if re.search(
                    r"(union|select|drop|delete)",
                    line.lower()
                ):

                    threats.append(
                        f"SQL Injection Attempt -> {line.strip()}"
                    )

    except Exception as e:

        threats.append(
            f"Error: {str(e)}"
        )

    return threats