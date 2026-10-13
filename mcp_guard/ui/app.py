"""The Textual application behind `mcp-guard ui`.

Layout: a tree of servers and tools on the left (riskiest first, colored by
risk), the selected item's details on the right, key bindings in the footer.
"""

from __future__ import annotations

from typing import Any, ClassVar

from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Horizontal, VerticalScroll
from textual.css.query import NoMatches
from textual.screen import ModalScreen
from textual.widgets import Footer, Header, Static, Tree

from ..pipeline import AuditRun, Loader
from ..text import printable
from .model import Group, Item, build_groups, detail, lock_report, risk_style, summary

DARK_THEME = "textual-dark"
LIGHT_THEME = "textual-light"


class LockScreen(ModalScreen[None]):
    """Lock status: the file in use and every change since it was written."""

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("escape,l,q", "dismiss", "Close"),
    ]
    DEFAULT_CSS = """
    LockScreen { align: center middle; }
    #lock-box { width: 90%; height: 80%; border: round $accent; background: $surface;
                padding: 1 2; }
    """

    def __init__(self, run: AuditRun) -> None:
        super().__init__()
        self._run = run

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="lock-box"):
            yield Static(lock_report(self._run), id="lock-report")
        yield Footer()

    async def action_dismiss(self, result: None = None) -> None:
        self.dismiss(result)


class AuditApp(App[None]):
    TITLE = "mcp-guard"
    CSS = """
    #panes { height: 1fr; }
    #tree { width: 2fr; min-width: 30; border: round $primary; }
    #tree:focus { border: round $accent; }
    #details { width: 3fr; border: round $primary; padding: 0 1; }
    #details:focus { border: round $accent; }
    """
    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("q", "quit", "Quit"),
        Binding("r", "refresh", "Refresh"),
        Binding("l", "show_lock", "Lock"),
        Binding("t", "toggle_theme", "Light/Dark"),
        Binding("tab", "focus_next", "Switch pane", show=True, priority=True),
    ]

    def __init__(self, run: AuditRun, loader: Loader | None = None) -> None:
        super().__init__()
        self.run_data = run
        self._loader = loader
        self.selected: Item | None = None

    # -- layout ---------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="panes"):
            tree: Tree[Item | None] = Tree("audit", id="tree")
            tree.show_root = False
            yield tree
            with VerticalScroll(id="details"):
                yield Static(detail(None), id="detail")
        yield Footer()

    def on_mount(self) -> None:
        self.theme = DARK_THEME
        self._populate()
        self.query_one("#tree", Tree).focus()

    @property
    def dark(self) -> bool:
        return self.current_theme.dark

    def _label(self, text: str, item: Item | Group) -> Text:
        return Text.assemble((f"{item.risk.name:<8}", risk_style(item.risk, self.dark)),
                             " ", printable(text, 120))

    def _populate(self) -> None:
        """(Re)build the tree, keeping the selected item if it still exists."""
        keep = (self.selected.kind, self.selected.label) if self.selected else None
        tree: Tree[Item | None] = self.query_one("#tree", Tree)
        tree.clear()
        nodes = []
        for group in build_groups(self.run_data):
            node = tree.root.add(self._label(group.title, group), data=group.server,
                                 expand=True)
            nodes.append(node)
            nodes += [node.add_leaf(self._label(item.name, item), data=item)
                      for item in group.tools]
        self.sub_title = summary(self.run_data)
        with_items = [(n, n.data) for n in nodes if n.data is not None]
        target = next((n for n, item in with_items if (item.kind, item.label) == keep),
                      with_items[0][0] if with_items else (nodes[0] if nodes else None))
        self._show(target.data if target is not None else None)
        if target is not None:
            # after the refresh: clearing the tree queues a highlight of line 0
            self.call_after_refresh(tree.move_cursor, target)

    def _show(self, item: Item | None) -> None:
        self.selected = item
        try:
            panel = self.query_one("#detail", Static)
        except NoMatches:  # an event delivered while the app is shutting down
            return
        panel.update(detail(item, self.dark))

    # -- events & actions ---------------------------------------------------------

    def on_tree_node_highlighted(self, event: Tree.NodeHighlighted[Any]) -> None:
        if event.node.is_root:  # hidden root, highlighted when the tree is cleared
            return
        self._show(event.node.data)

    def action_toggle_theme(self) -> None:
        self.theme = LIGHT_THEME if self.dark else DARK_THEME
        self._populate()  # risk colors depend on the background

    def action_show_lock(self) -> None:
        self.push_screen(LockScreen(self.run_data))

    def action_refresh(self) -> None:
        if self._loader is None:
            self.notify("Nothing to refresh.", severity="warning")
            return
        self.notify("Refreshing...")
        self._reload()

    @work(thread=True, exclusive=True)
    def _reload(self) -> None:
        if self._loader is None:
            return
        try:
            run = self._loader()
        except Exception as exc:  # noqa: BLE001 - shown to the user, app stays usable
            self.call_from_thread(self.notify, f"Refresh failed: {printable(str(exc), 200)}",
                                  severity="error")
            return
        self.call_from_thread(self._apply, run)

    def _apply(self, run: AuditRun) -> None:
        self.run_data = run
        self._populate()
        self.notify("Refreshed.")
