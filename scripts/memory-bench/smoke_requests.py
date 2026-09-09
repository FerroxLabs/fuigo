"""Classify the fixture's auxiliary title call without hiding main recall calls."""

def is_title_request(request):
    choice = request.get("tool_choice")
    tools = request.get("tools", [])
    return (
        isinstance(choice, dict)
        and choice.get("type") == "function"
        and choice.get("function", {}).get("name") == "session_title"
        and len(tools) == 1
        and tools[0].get("function", {}).get("name") == "session_title"
    )


def is_recall_request(request):
    return not is_title_request(request) and any(
        message.get("role") == "user" and "CURRENT" in (message.get("content") or "")
        for message in request.get("messages", [])
    )
