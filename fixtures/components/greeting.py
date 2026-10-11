"""Synthetic local component, not a third-party package or production service."""


def greet(name: str) -> str:
    if not isinstance(name, str) or not name.strip() or len(name) > 40:
        raise ValueError("Use a short, non-empty synthetic name")
    return "Hello, " + name.strip() + "!"


if __name__ == "__main__":
    print(greet("synthetic learner"))
