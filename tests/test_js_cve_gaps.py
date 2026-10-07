"""Detection gaps from the first OpenSSF CVE slice, reduced to synthetic snippets.

These are the patterns the labelled fixes actually changed, not a score for that slice.
Source here is fixture data and is parsed, never executed.
"""

from __future__ import annotations

from polaris.review.analyzers import AnalysisRuntime
from polaris.review.engine import WorkflowReviewer

MEMORY = AnalysisRuntime(allow_external_analyzers=False, allow_temporary_source_files=False)


def rules(code: str, path: str = "app.js") -> set[tuple[str, str]]:
    report = WorkflowReviewer(runtime=MEMORY).review_snippet(code, path=path)
    return {(item.result, item.rule_id) for item in report.findings}


def test_returned_middleware_treats_req_url_as_a_path_source():
    code = (
        'var fs = require("fs");\n'
        'var url = require("url");\n'
        "module.exports = function (options) {\n"
        "  var handler = function (req, res, next) {\n"
        "    var resource = url.parse(req.url);\n"
        "    var filePath = process.cwd() + (resource.pathname || '/');\n"
        "    fs.stat(filePath, function () {});\n"
        "  };\n"
        "  return handler;\n"
        "};\n"
    )
    assert ("flagged", "polaris.js.path_traversal.fs") in rules(code)
    safe = code.replace("process.cwd() + (resource.pathname || '/')", '"/var/static/index.html"')
    assert ("flagged", "polaris.js.path_traversal.fs") not in rules(safe)


def test_a_public_function_that_interpolates_into_a_shell_is_flagged():
    code = (
        'const { exec } = require("child_process");\n'
        "exports.findLoad = function findLoad(arg, cb) {\n"
        "  exec(`wmic | findstr /c:${arg}`, cb);\n"
        "};\n"
    )
    assert ("flagged", "polaris.js.command_injection.shell") in rules(code)
    # An argument array is not the same bug: callers can still pass a single argument.
    listed = (
        'const { execFile } = require("child_process");\n'
        "exports.findLoad = function findLoad(arg, cb) {\n"
        '  execFile("wmic", ["process", arg], cb);\n'
        "};\n"
    )
    assert ("flagged", "polaris.js.command_injection.shell") not in rules(listed)
    method = (
        'var exec = require("child_process").exec;\n'
        "var stats = {\n"
        "  ps: function (pid, options, done) {\n"
        "    exec('ps -p ' + pid, done);\n"
        "  }\n"
        "};\n"
        "module.exports = stats;\n"
    )
    assert ("flagged", "polaris.js.command_injection.shell") in rules(method)


def test_escaping_metacharacters_before_a_regexp_is_not_a_finding():
    local = 'function escape(s) {\n  return s.replace(/[.*+?^${}()|[\\]\\\\]/g, "\\\\$&");\n}\nexport function extract(name) {\n  return new RegExp(\'\\\\b\' + escape(name) + \'\\\\b\');\n}\n'
    assert ("flagged", "polaris.js.code_injection.regexp") not in rules(local)
    library = (
        "const escapeStringRegexp = require('escape-string-regexp');\n"
        "module.exports = function (str, sep) {\n"
        "  return new RegExp('(' + escapeStringRegexp(sep) + ')');\n"
        "};\n"
    )
    assert ("flagged", "polaris.js.code_injection.regexp") not in rules(library)


def test_a_public_function_that_builds_a_regexp_from_its_argument_is_flagged():
    code = (
        "module.exports = function (str, sep) {\n"
        "  return str.replace(new RegExp('(' + sep + '[A-Z])', 'g'), sep);\n"
        "};\n"
    )
    assert ("flagged", "polaris.js.code_injection.regexp") in rules(code)
    fixed = code.replace("'(' + sep + '[A-Z])'", "'([A-Z])'")
    assert ("flagged", "polaris.js.code_injection.regexp") not in rules(fixed)


def test_jquery_inside_an_iife_is_still_xss():
    bad = (
        "const Util = (($) => {\n"
        "  const api = {\n"
        "    getSelectorFromElement(element) {\n"
        "      const selector = element.getAttribute('href');\n"
        "      return $(selector);\n"
        "    }\n"
        "  };\n"
        "  return api;\n"
        "})(jQuery);\n"
    )
    assert ("flagged", "polaris.js.xss.jquery_html") in rules(bad)
    fixed = bad.replace("$(selector)", "$(document).find(selector)")
    assert ("flagged", "polaris.js.xss.jquery_html") not in rules(fixed)


def test_a_shell_export_inside_an_iife_is_still_flagged():
    code = (
        "(function () {\n"
        "  var exec = require('child_process').exec;\n"
        "  exports.findLoad = function findLoad(arg, cb) {\n"
        "    exec('wmic | findstr /c:' + arg, cb);\n"
        "  };\n"
        "})();\n"
    )
    assert ("flagged", "polaris.js.command_injection.shell") in rules(code)


def test_jquery_dollar_call_of_an_attribute_is_xss_and_find_is_not():
    bad = (
        "function getSelectorFromElement(element) {\n"
        "  const selector = element.getAttribute('href');\n"
        "  return $(selector);\n"
        "}\n"
    )
    assert ("flagged", "polaris.js.xss.jquery_html") in rules(bad)
    fixed = bad.replace("$(selector)", "$(document).find(selector)")
    assert ("flagged", "polaris.js.xss.jquery_html") not in rules(fixed)
    assert ("flagged", "polaris.js.xss.jquery_html") not in rules("const node = $(document);\n")


def test_math_random_in_an_id_generator_is_flagged_and_a_paint_loop_is_not():
    assert ("flagged", "polaris.js.insecure_auth_crypto.weak_random") in rules(
        "function generateId() {\n  return Math.random().toString();\n}\n")
    assert ("flagged", "polaris.js.insecure_auth_crypto.weak_random") in rules(
        "function randomatic(pattern) {\n  return pattern.charAt(Math.random() * 10);\n}\n")
    nested = (
        "function randomatic(pattern, length) {\n"
        "  var res = '';\n"
        "  while (length--) {\n"
        "    res += mask.charAt(parseInt(Math.random() * mask.length, 10));\n"
        "  }\n"
        "  return res;\n"
        "}\n"
    )
    assert ("flagged", "polaris.js.insecure_auth_crypto.weak_random") in rules(nested)
    assert ("flagged", "polaris.js.insecure_auth_crypto.weak_random") not in rules(
        "function paint() {\n  return Math.random();\n}\n")
    assert ("flagged", "polaris.js.insecure_auth_crypto.weak_random") not in rules(
        "function paint() {\n  return items.map(function () { return Math.random(); });\n}\n")


def test_strict_ssl_false_and_a_cleartext_installer_url_are_flagged():
    assert ("flagged", "polaris.js.unsafe_security_configuration.tls_disabled") in rules(
        "download(url, { strictSSL: false });\n")
    assert ("flagged", "polaris.js.unsafe_security_configuration.cleartext_download") in rules(
        "var tools = { installerUrl: 'http://download.example/tool.exe' };\n")
    assert ("flagged", "polaris.js.unsafe_security_configuration.cleartext_download") not in rules(
        "var tools = { installerUrl: 'https://download.example/tool.exe' };\n")
    assert ("flagged", "polaris.js.unsafe_security_configuration.cleartext_download") not in rules(
        "var local = { installerUrl: 'http://127.0.0.1/tool.exe' };\n")
