from tfa.code_generator import hex_codes_generator


def main():
    """Main function, creates a code and prints it on the console."""
    code: str = hex_codes_generator()
    print(code)


if __name__ == "__main__":
    main()
