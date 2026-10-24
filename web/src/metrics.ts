// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

export interface Sample {
  labels: [name: string, value: string][];
  /** The value as the server wrote it. */
  value: string;
}

export interface Family {
  name: string;
  help: string;
  type: string;
  samples: Sample[];
}

export interface Metrics {
  families: Family[];
}

const sample = /^([A-Za-z_:][A-Za-z0-9_:]*)(?:\{(.*)\})?[ \t]+(\S+)(?:[ \t]+-?\d+)?$/;
const label = /([A-Za-z_][A-Za-z0-9_]*)="((?:[^"\\]|\\.)*)"/y;
const number = /^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$|^[+-]?Inf$|^NaN$/;

function unescape(text: string, quotes: boolean): string {
  return text.replace(/\\(.)/g, (_, c: string) => (c === 'n' ? '\n' : c === '\\' || (quotes && c === '"') ? c : `\\${c}`));
}

/** Reads the labels between the braces of a sample, or nothing if they are not a list of name="value" pairs. */
function labelsOf(inner: string): [string, string][] | undefined {
  const out: [string, string][] = [];
  let at = 0;
  while (at < inner.length) {
    label.lastIndex = at;
    const match = label.exec(inner);
    if (match === null) {
      return undefined;
    }
    out.push([match[1] ?? '', unescape(match[2] ?? '', true)]);
    at = label.lastIndex;
    if (inner[at] === ',') {
      at++;
    } else if (at < inner.length) {
      return undefined;
    }
  }
  return out;
}

/**
 * Reads the text format of Prometheus, version 0.0.4, as far as Nyktus writes it:
 * gauges, with help and type lines and labels. A line that does not fit is left
 * out, so that nothing is taken for more than it is.
 */
export function parseMetrics(text: string): Metrics {
  const families = new Map<string, Family>();
  const family = (name: string): Family => {
    let found = families.get(name);
    if (found === undefined) {
      found = { name, help: '', type: '', samples: [] };
      families.set(name, found);
    }
    return found;
  };

  for (const line of text.split(/\r?\n/)) {
    if (line.trim() === '') {
      continue;
    }
    const meta = /^# (HELP|TYPE) ([A-Za-z_:][A-Za-z0-9_:]*)(?: (.*))?$/.exec(line);
    if (meta !== null) {
      const target = family(meta[2] ?? '');
      if (meta[1] === 'HELP') {
        target.help = unescape(meta[3] ?? '', false);
      } else {
        target.type = meta[3] ?? '';
      }
      continue;
    }
    const match = sample.exec(line);
    const labels = match === null ? undefined : match[2] === undefined ? [] : labelsOf(match[2]);
    if (match === null || labels === undefined || !number.test(match[3] ?? '')) {
      continue;
    }
    family(match[1] ?? '').samples.push({ labels, value: match[3] ?? '' });
  }
  return { families: [...families.values()] };
}
