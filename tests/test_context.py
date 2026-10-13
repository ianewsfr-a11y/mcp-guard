"""v0.4: word forms and contextual exceptions (lexical false positives)."""

import pytest

from mcp_guard import ConfigFormatError, Risk, audit, load_ruleset
from mcp_guard.context import effective_tokens, word_forms


def _tool(name, description=""):
    (entry,) = audit({"tools": [{"name": name, "description": description}]})
    return entry


def _categories(entry):
    return {f.category for f in entry.findings}


@pytest.mark.unit
@pytest.mark.parametrize("token,expected", [
    ("deletes", {"delete"}), ("queries", {"query"}), ("executes", {"execute"}),
    ("writes", {"write"}), ("removes", {"remove"}),
])
def test_word_forms_find_base_forms(token, expected):
    assert expected <= word_forms(token)


@pytest.mark.unit
@pytest.mark.parametrize("token,forbidden", [
    ("process", "proces"), ("status", "statu"), ("analysis", "analysi"),
    ("posts", "post"), ("updates", "update"), ("tables", "table"),
    ("created", "create"), ("saved", "save"), ("writing", "write"),
])
def test_word_forms_avoid_bad_stems(token, forbidden):
    assert forbidden not in word_forms(token)


@pytest.mark.unit
def test_word_forms_limited_to_vocabulary():
    assert word_forms("bashes", frozenset({"bash"})) == {"bashes", "bash"}
    assert word_forms("bashes", frozenset()) == {"bashes"}


# --- false positives fixed ----------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize("name,description,absent", [
    ("add_numbers", "Add two numbers.", "write-operation"),
    ("add", "Add two integers and return the sum.", "write-operation"),
    ("add_days", "Add a number of days to a date.", "write-operation"),
    ("remove_duplicates", "Remove duplicate items from a list.", "write-operation"),
    ("replace_text", "Replace a substring in a string using a regex.", "write-operation"),
    ("truncate", "Truncate text to N characters.", "write-operation"),
    ("move_mouse", "Move the mouse cursor to x, y.", "write-operation"),
    ("edit_distance", "Compute the edit distance between two words.", "write-operation"),
    ("execute_query", "Execute a SQL query and return the rows.", "command-execution"),
    ("find_root_dir", "Return the root directory of the repo.", "privileged-access"),
    ("root_cause", "Suggest the root cause of an error.", "privileged-access"),
    ("post_process", "Post-process model output.", "network"),
    ("format_table", "Render rows as a markdown table.", "database"),
    ("get_pull_request", "Read a pull request.", "network"),
])
def test_lexical_false_positives_are_gone(name, description, absent):
    assert absent not in _categories(_tool(name, description))


@pytest.mark.unit
def test_add_two_numbers_is_low():
    assert _tool("add_numbers", "Add two numbers.").risk == Risk.LOW


# --- true positives kept ------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize("name,description,category", [
    ("add_observations", "Add new observations to existing entities.", "write-operation"),
    ("add_user", "Add a user to the database.", "write-operation"),
    ("remove_file", "Remove a file from disk.", "write-operation"),
    ("execute_command", "Execute a shell command.", "command-execution"),
    ("run_as_root", "Runs the script as root.", "privileged-access"),
    ("delete_rows", "Deletes rows from a SQL table.", "database-write"),
    ("publish", "Posts the message to a webhook.", "network"),
    ("cleanup", "Deletes temporary files.", "write-operation"),
    # the name is only excused when the description uses the word harmlessly
    ("replace_text", "Replace text in a file on disk.", "write-operation"),
])
def test_true_positives_are_kept(name, description, category):
    assert category in _categories(_tool(name, description))


@pytest.mark.unit
def test_inflections_now_match():
    """v0.3 missed "Deletes a file" (token `deletes` is not `delete`)."""
    assert _tool("cleanup", "Deletes a file.").risk == Risk.HIGH


@pytest.mark.unit
def test_effective_tokens_drop_only_excepted_occurrences():
    tokens = effective_tokens(["add two numbers and write the file"],
                              {"add": frozenset({"numbers"})})
    assert "add" not in tokens and "write" in tokens
    # a second, unexcused occurrence keeps the keyword
    tokens = effective_tokens(["add two numbers. Later it can also add the user"],
                              {"add": frozenset({"numbers"})})
    assert "add" in tokens


# --- context words elsewhere must not hide a dangerous keyword --------------------


@pytest.mark.unit
@pytest.mark.parametrize("name,description,category", [
    ("run", "Execute any command on the host. Supports SQL queries too.",
     "command-execution"),
    ("run", "Execute arbitrary commands. Search the web.", "command-execution"),
    ("run_as_root", "Runs with root privileges (see the project root directory).",
     "privileged-access"),
    ("admin", "Root access to the machine; also does root cause analysis.",
     "privileged-access"),
    ("add_user", "Add a user to the system. Works with two numbers.", "write-operation"),
    ("cleanup", "Remove any file. Supports string output.", "write-operation"),
])
def test_context_words_elsewhere_do_not_evade_detection(name, description, category):
    assert category in _categories(_tool(name, description))


@pytest.mark.unit
@pytest.mark.parametrize("name,description", [
    ("get_feed", "Latest updates and created date, last modified."),
    ("list_items", "Returns saved items and stored values."),
    ("list_posts", "Returns recent blog posts."),
])
def test_stemming_adds_no_false_positive(name, description):
    assert _tool(name, description).risk == Risk.LOW


# --- rules file -----------------------------------------------------------------


def _ruleset(tmp_path, content):
    path = tmp_path / "rules.yaml"
    path.write_text(content, encoding="utf-8")
    return load_ruleset(path)


@pytest.mark.unit
def test_custom_exceptions_extend_defaults(tmp_path):
    ruleset = _ruleset(tmp_path, "exceptions:\n  create: [ticket, tickets]\n")
    (entry,) = audit({"tools": [{"name": "create_ticket"}]}, ruleset)
    assert entry.findings == ()
    (entry,) = audit({"tools": [{"name": "add_numbers"}]}, ruleset)
    assert entry.findings == ()  # defaults still apply


@pytest.mark.unit
def test_extends_none_drops_default_exceptions(tmp_path):
    ruleset = _ruleset(tmp_path, "extends: none\nrules:\n"
                                 "  - {category: w, risk: HIGH, keywords: [add]}\n")
    (entry,) = audit({"tools": [{"name": "add_numbers"}]}, ruleset)
    assert entry.risk == Risk.HIGH


@pytest.mark.unit
def test_exception_words_are_validated(tmp_path):
    with pytest.raises(ConfigFormatError, match="single words"):
        _ruleset(tmp_path, "exceptions:\n  add: [two-numbers]\n")
