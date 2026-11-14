// Shared DOM/keyboard adapter over the Rust-filtered metadata view. No matching,
// text filtering, ranking, usage writes or secret requests live in this module.
export const LOGIN_ROW_HEIGHT = 48;
export function visibleWindow(total, scrollTop, height, rowHeight, overscan) {
  const top = Math.min(Math.max(0, scrollTop), Math.max(0, total * rowHeight - height));
  return { start: Math.max(0, Math.floor(top / rowHeight) - overscan), end: Math.min(total, Math.ceil((top + height) / rowHeight) + overscan) };
}
export class VirtualLoginList {
  constructor({ root, search, input, count, empty, maxHeight, messages, onError }) {
    Object.assign(this, { root, search, input, count, empty, maxHeight, messages, onError });
    this.revision = 0; this.disabled = true; this.selected = -1; this.model = null;
    this.spacer = document.createElement('div'); this.spacer.className = 'login-space';
    this.layer = document.createElement('div'); this.layer.className = 'login-window';
    this.spacer.append(this.layer); root.replaceChildren(this.spacer);
    root.classList.add('login-list'); root.setAttribute('role', 'listbox');
    root.style.setProperty('--login-row-height', `${LOGIN_ROW_HEIGHT}px`);
    input.setAttribute('role', 'combobox'); input.setAttribute('aria-autocomplete', 'list');
    input.setAttribute('aria-controls', root.id); input.setAttribute('aria-expanded', 'false');
    input.addEventListener('input', () => this.boundary(() => {
      if (!this.model) return;
      this.revision++; this.model.filter(input.value); this.selected = this.model.count() ? 0 : -1;
      root.scrollTop = 0; this.render();
    }));
    const keyboard = event => {
      if (!event.isTrusted || event.isComposing || (event.key === 'Enter' && event.target instanceof HTMLButtonElement)) return;
      if (event.target === input && input.value && ['Home', 'End'].includes(event.key)) return;
      if (this.key(event.key)) { event.preventDefault(); event.stopPropagation(); }
    };
    input.addEventListener('keydown', keyboard); root.addEventListener('keydown', keyboard);
    root.addEventListener('scroll', () => {
      if (this.animation !== undefined) return;
      this.animation = requestAnimationFrame(() => { this.animation = undefined; this.boundary(() => this.render()); });
    });
    this.clear();
  }
  boundary(operation) {
    try { operation(); }
    catch (error) { this.clear(); this.failure = error; this.onError(error); }
  }
  clear() {
    this.revision++; this.model?.free(); this.model = null; this.selected = -1; this.disabled = true;
    if (this.animation !== undefined) cancelAnimationFrame(this.animation); this.animation = undefined;
    this.input.value = ''; this.input.disabled = true; this.input.removeAttribute('aria-activedescendant'); this.root.removeAttribute('aria-activedescendant');
    this.input.setAttribute('aria-expanded', 'false'); this.search.hidden = true; this.root.hidden = true;
    this.empty.hidden = true; this.count.textContent = ''; this.layer.replaceChildren(); this.spacer.style.height = '0px';
    this.onFill = null; this.failure = null;
  }
  setModel(model, onFill) {
    this.clear(); this.model = model; this.onFill = onFill;
    this.selected = model.count() ? 0 : -1; this.input.maxLength = model.query_limit();
    this.search.hidden = model.total() * LOGIN_ROW_HEIGHT <= this.maxHeight;
    this.root.tabIndex = this.search.hidden ? 0 : -1;
    this.input.disabled = false; this.disabled = false; this.root.scrollTop = 0; this.render();
  }
  setDisabled(disabled) {
    this.disabled = disabled;
    for (const row of this.layer.children) row.disabled = disabled;
  }
  fill(index) {
    if (this.disabled || !this.model || index < 0 || index >= this.model.count()) return;
    const [item] = JSON.parse(this.model.window(index, 1));
    this.onFill(item);
  }
  key(key) {
    if (this.disabled || !this.model || !this.model.count()) return false;
    const size = this.model.count(), page = Math.max(1, Math.floor(this.maxHeight / LOGIN_ROW_HEIGHT));
    switch (key) {
      case 'ArrowDown': this.selected = (this.selected + 1) % size; break;
      case 'ArrowUp': this.selected = (this.selected - 1 + size) % size; break;
      case 'Home': this.selected = 0; break;
      case 'End': this.selected = size - 1; break;
      case 'PageDown': this.selected = Math.min(size - 1, this.selected + page); break;
      case 'PageUp': this.selected = Math.max(0, this.selected - page); break;
      case 'Enter': this.fill(this.selected); return true;
      default: return false;
    }
    const top = this.selected * LOGIN_ROW_HEIGHT, bottom = top + LOGIN_ROW_HEIGHT;
    if (top < this.root.scrollTop) this.root.scrollTop = top;
    else if (bottom > this.root.scrollTop + this.height) this.root.scrollTop = bottom - this.height;
    this.render(); return true;
  }
  render() {
    if (!this.model) return;
    const total = this.model.total(), count = this.model.count();
    this.count.textContent = this.messages.count(count, total);
    this.empty.hidden = count !== 0; this.empty.textContent = total ? this.messages.noResults : this.messages.empty;
    this.root.hidden = count === 0; this.input.setAttribute('aria-expanded', String(count > 0));
    this.height = Math.min(count * LOGIN_ROW_HEIGHT, this.maxHeight);
    this.root.style.height = `${this.height}px`; this.spacer.style.height = `${count * LOGIN_ROW_HEIGHT}px`;
    const { start, end } = visibleWindow(count, this.root.scrollTop, this.height, LOGIN_ROW_HEIGHT, 2);
    const rows = JSON.parse(this.model.window(start, end - start));
    const revision = this.revision, focused = this.layer.contains(document.activeElement) ? document.activeElement.dataset.index : null;
    this.layer.style.transform = `translateY(${start * LOGIN_ROW_HEIGHT}px)`;
    this.layer.replaceChildren(...rows.map((item, offset) => {
      const index = start + offset, button = document.createElement('button');
      button.type = 'button'; button.className = 'match'; button.tabIndex = -1; button.disabled = this.disabled;
      button.id = `${this.root.id}-row-${index}`; button.dataset.index = String(index); button.setAttribute('role', 'option');
      button.setAttribute('aria-posinset', String(index + 1)); button.setAttribute('aria-setsize', String(count));
      button.setAttribute('aria-selected', String(index === this.selected));
      const avatar = document.createElement('span'); avatar.className = 'avatar'; avatar.setAttribute('aria-hidden', 'true');
      avatar.textContent = Array.from(item.username || item.title)[0]?.toUpperCase() ?? '';
      const copy = document.createElement('span'); copy.className = 'copy';
      const user = document.createElement('span'); user.className = 'user'; user.textContent = item.username || item.title;
      const name = document.createElement('span'); name.className = 'name'; name.textContent = item.title; name.hidden = !item.username;
      button.title = item.username ? `${item.username} — ${item.title}` : item.title;
      copy.append(user, name); button.append(avatar, copy);
      button.addEventListener('click', event => { if (event.isTrusted && this.revision === revision) this.fill(index); });
      return button;
    }));
    const selected = document.getElementById(`${this.root.id}-row-${this.selected}`);
    for (const target of [this.input, this.root]) {
      if (selected) target.setAttribute('aria-activedescendant', selected.id); else target.removeAttribute('aria-activedescendant');
    }
    if (focused !== null) {
      const replacement = this.layer.querySelector(`[data-index="${focused}"]`);
      (replacement ?? this.input).focus({ preventScroll: true });
    }
  }
}
