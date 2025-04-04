from transformers import pipeline

def test_huggingface_api():
    # Initialize the Hugging Face pipeline with a question-answering model
    qa_pipeline = pipeline("question-answering", model="distilbert-base-uncased-distilled-squad")

    # Get user input
    user_input = input("Enter your cybersecurity-related question: ")

    try:
        # Provide context for the question
        context = """
        Cybersecurity involves protecting computer systems, networks, and data from digital attacks, unauthorized access, and damage. 
        It includes practices such as using firewalls, encryption, multi-factor authentication, and regular software updates to safeguard 
        sensitive information and ensure the integrity, confidentiality, and availability of data.
        """

        # Create a question-answering task
        result = qa_pipeline(question=user_input, context=context)

        # Print the response
        print("Generated response:", result['answer'])
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    test_huggingface_api()