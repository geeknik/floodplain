/*
 * floodplain.notify.js - toast notifications and confirm dialogs.
 *
 * Replaces AlertifyJS (GPL-3.0) with a small MIT-licensed helper built on the
 * Bootstrap 3 alert and modal components that the UI already ships.
 *
 * Security: every string passed in is rendered with textContent, never as
 * HTML, because messages can contain server responses and scan data.
 *
 * API:
 *   sf.notify.success(title, lines)
 *   sf.notify.error(title, lines)
 *   sf.notify.message(text)
 *   sf.notify.confirm(title, text, items, onConfirm)
 *
 * `lines` and `items` are optional strings or arrays of strings.
 */
(function (global) {
  "use strict";

  var sf = global.sf = global.sf || {};
  var TOAST_MS = 6000;
  var MAX_ITEMS = 50;

  function asList(value) {
    if (value === undefined || value === null || value === "") {
      return [];
    }
    return Array.isArray(value) ? value : [value];
  }

  function textEl(tag, text, className) {
    var el = document.createElement(tag);
    if (className) {
      el.className = className;
    }
    el.textContent = String(text);
    return el;
  }

  function container() {
    var c = document.getElementById("fp-notify");
    if (!c) {
      c = document.createElement("div");
      c.id = "fp-notify";
      c.setAttribute("role", "status");
      c.setAttribute("aria-live", "polite");
      c.style.cssText = "position:fixed;top:60px;right:20px;z-index:2000;width:360px;max-width:90vw;";
      document.body.appendChild(c);
    }
    return c;
  }

  function appendItems(parent, items) {
    var list = asList(items);
    if (!list.length) {
      return;
    }
    var ul = document.createElement("ul");
    ul.style.cssText = "margin:8px 0 0 0;padding-left:18px;max-height:200px;overflow:auto;word-break:break-all;";
    list.slice(0, MAX_ITEMS).forEach(function (item) {
      ul.appendChild(textEl("li", item));
    });
    if (list.length > MAX_ITEMS) {
      ul.appendChild(textEl("li", "… and " + (list.length - MAX_ITEMS) + " more"));
    }
    parent.appendChild(ul);
  }

  function toast(kind, title, lines) {
    var el = document.createElement("div");
    el.className = "alert alert-" + kind + " alert-dismissible fp-toast";
    el.style.cssText = "box-shadow:0 2px 8px rgba(0,0,0,.25);word-wrap:break-word;";

    var close = document.createElement("button");
    close.type = "button";
    close.className = "close";
    close.setAttribute("aria-label", "Close");
    close.textContent = "×";
    close.addEventListener("click", function () { el.remove(); });
    el.appendChild(close);

    if (title) {
      el.appendChild(textEl("strong", title));
    }
    var list = asList(lines);
    if (list.length === 1) {
      el.appendChild(textEl("div", list[0]));
    } else {
      appendItems(el, list);
    }

    container().appendChild(el);
    setTimeout(function () { el.remove(); }, kind === "danger" ? TOAST_MS * 2 : TOAST_MS);
    return el;
  }

  function confirmDialog(title, text, items, onConfirm) {
    var modal = document.createElement("div");
    modal.className = "modal fade fp-confirm";
    modal.setAttribute("tabindex", "-1");
    // The themes style `.fade.in` with an opaque background (dark.css uses
    // !important), which would paint this full-screen element solid and hide
    // the page. Inline !important keeps the Bootstrap backdrop visible.
    modal.style.setProperty("background", "transparent", "important");
    modal.setAttribute("role", "dialog");

    var dialog = document.createElement("div");
    dialog.className = "modal-dialog";
    var content = document.createElement("div");
    content.className = "modal-content";

    var header = document.createElement("div");
    header.className = "modal-header";
    header.appendChild(textEl("h4", title || "Are you sure?", "modal-title"));

    var body = document.createElement("div");
    body.className = "modal-body";
    body.appendChild(textEl("p", text));
    appendItems(body, items);

    var footer = document.createElement("div");
    footer.className = "modal-footer";
    var cancel = textEl("button", "Cancel", "btn btn-default fp-cancel");
    cancel.type = "button";
    cancel.setAttribute("data-dismiss", "modal");
    var ok = textEl("button", "OK", "btn btn-danger fp-ok");
    ok.type = "button";
    footer.appendChild(cancel);
    footer.appendChild(ok);

    content.appendChild(header);
    content.appendChild(body);
    content.appendChild(footer);
    dialog.appendChild(content);
    modal.appendChild(dialog);
    document.body.appendChild(modal);

    var $modal = global.jQuery(modal);
    ok.addEventListener("click", function () {
      $modal.modal("hide");
      if (typeof onConfirm === "function") {
        onConfirm();
      }
    });
    $modal.on("hidden.bs.modal", function () { modal.remove(); });
    $modal.modal("show");
    return modal;
  }

  sf.notify = {
    success: function (title, lines) { return toast("success", title, lines); },
    error: function (title, lines) { return toast("danger", title, lines); },
    message: function (text) { return toast("info", null, text); },
    confirm: confirmDialog
  };
})(window);
