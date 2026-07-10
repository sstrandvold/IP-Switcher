import queue
import threading


def run_async(widget, work, on_done, on_busy=None, on_idle=None):
    """Run `work` on a background thread and deliver its result on the Tk main loop.

    `widget` only needs `.after()` and `.winfo_exists()` - any Tk widget or window
    works, so tool dialogs can reuse this instead of writing their own thread+queue
    polling loop. `on_done(kind, payload)` receives ("ok", result) or ("error", exc).
    """
    if on_busy:
        on_busy()
    result_queue = queue.Queue()

    def worker():
        try:
            result_queue.put(("ok", work()))
        except Exception as exc:
            result_queue.put(("error", exc))

    threading.Thread(target=worker, daemon=True).start()

    def poll():
        try:
            kind, payload = result_queue.get_nowait()
        except queue.Empty:
            if widget.winfo_exists():
                widget.after(100, poll)
            return
        if on_idle:
            on_idle()
        on_done(kind, payload)

    widget.after(100, poll)
