# Fixed target-side filesystem collector. Bash 4.2+ and GNU utilities; no Python.
# Arguments are generated as literal argv by bash_fs.py, never evaluated as code.
action=$1 root=$2 pattern=$3 budget=$4 lines=$5 start_line=$6 byte_offset=$7
tail_mode=$8 depth=$9 limit=${10} offset=${11} max_file=${12} literal=${13}
case_sensitive=${14} hidden=${15} respect_ignore=${16} scan_limit=${17}
scan_bytes=${18} wire_limit=${19} glob_pattern=${20}
context_lines=${21} rg_command=${22}
shift 22
n=$1; shift; paths=("${@:1:n}"); shift "$n"
n=$1; shift; includes=("${@:1:n}"); shift "$n"
n=$1; shift; excludes=("${@:1:n}"); shift "$n"
seen=0 matched=0 stopped=0 scan_limited=0 depth_limited=0 wire_used=0
page_used=0 page_rows=0
skipped_large=0 skipped_binary=0 scanned_bytes=0 engine=bash ignore_applied=0
started=${EPOCHREALTIME:-$SECONDS}
set -o pipefail

emit() {
    local LC_ALL=C value size=0
    for value in "$@"; do size=$((size + ${#value} + 1)); done
    if (( wire_used + size > wire_limit )); then
        scan_limited=1 stopped=1
        return 1
    fi
    wire_used=$((wire_used + size))
    if [[ $1 == I || $1 == G || $1 == L ]]; then
        # These raw records are a lower bound on their final JSON row size.
        # Keep one lookahead row so the local formatter can prove continuation.
        (( page_rows > 0 && page_used >= budget )) && stopped=1
        page_used=$((page_used + size))
        page_rows=$((page_rows + 1))
    fi
    printf '%s\0' "$@"
}

error() { emit E "$1" "$2" "$3"; }

meta() {
    local raw
    local -a flags=()
    [[ $1 == -L ]] && flags=(-L)
    if ! raw=$(LC_ALL=C stat "${flags[@]}" --printf='%f %s %Y %u %g %y' -- "$2" 2>&1); then
        meta_error=$raw
        return 1
    fi
    local seconds stamp fraction=0
    read -r mode size seconds uid gid stamp <<< "$raw"
    if [[ ! $mode =~ ^[[:xdigit:]]+$ || ! $size =~ ^[0-9]+$ || ! $seconds =~ ^-?[0-9]+$ ]]; then
        meta_error='invalid stat response'
        return 1
    fi
    if [[ $stamp =~ \.([0-9]{9}) ]]; then fraction=${BASH_REMATCH[1]}; fi
    mtime=$((seconds * 1000000000 + 10#$fraction))
}

stat_error() {
    local kind=OSError
    [[ $meta_error == *'No such file or directory'* ]] && kind=FileNotFoundError
    [[ $meta_error == *'Permission denied'* ]] && kind=PermissionError
    [[ $meta_error == *'Not a directory'* ]] && kind=NotADirectoryError
    error "$1" "$kind" "$meta_error"
}

info() {
    local p=$1 rel=$2 level=$3 link='' resolved=''
    if ! meta '' "$p"; then stat_error "$p"; return; fi
    if (( (16#$mode & 0170000) == 0120000 )); then
        link=$(readlink -n -- "$p" && printf '\1') || { error "$p" OSError 'readlink failed'; return; }
        link=${link%$'\1'}
        resolved=$(readlink -mn -- "$p" && printf '\1') || { error "$p" OSError 'path resolution failed'; return; }
        resolved=${resolved%$'\1'}
    fi
    emit I "$p" "$rel" "$level" "$mode" "$size" "$mtime" "$uid" "$gid" "$link" "$resolved"
}

accept() {
    matched=$((matched + 1))
    (( matched <= offset )) && return 1
    (( matched >= offset + limit + 1 )) && stopped=1
    return 0
}

match_any() {
    local value=$1 p; shift
    for p in "$@"; do
        if [[ $value == $p || ${value##*/} == $p ]]; then return 0; fi
        if [[ $p == '**/'* && $value == ${p:3} ]]; then return 0; fi
    done
    return 1
}

selected() {
    (( ${#includes[@]} == 0 )) || match_any "$1" "${includes[@]}"
}

open_regular() {
    local p=$1
    if [[ ! -e $p && ! -L $p ]]; then error "$p" FileNotFoundError 'file does not exist'; return 1; fi
    if [[ ! -f $p ]]; then error "$p" ValueError 'only regular files can be read/checksummed'; return 1; fi
    if ! exec {file_fd}<"$p"; then error "$p" PermissionError 'cannot open file for reading'; return 1; fi
    fd_path=/proc/$$/fd/$file_fd
    if ! meta -L "$fd_path"; then stat_error "$p"; exec {file_fd}<&-; return 1; fi
    if (( (16#$mode & 0170000) != 0100000 )); then
        error "$p" ValueError 'only regular files can be read/checksummed'
        exec {file_fd}<&-
        return 1
    fi
}

binary() {
    local codes
    head -c 8192 -- "$fd_path" | od -An -v -t x1 | grep -Eq '(^|[[:space:]])00([[:space:]]|$)'
    codes=("${PIPESTATUS[@]}")
    [[ ${codes[2]} == 0 ]]
}

read_file() {
    local p=$1 allowance=$2 before_size before_mtime start previous='' data count
    open_regular "$p" || return
    before_size=$size before_mtime=$mtime
    if binary; then
        error "$p" ValueError 'binary file; use download for binary content'
        exec {file_fd}<&-
        return
    fi
    if (( tail_mode )); then
        start=$((before_size > allowance ? before_size - allowance : 0))
        count=$allowance
    elif (( byte_offset >= 0 )); then
        start=$((byte_offset < before_size ? byte_offset : before_size))
        count=$((allowance + 3))
    else
        start=0 count=$((allowance + 3))
        if (( start_line > 1 )); then
            start=$(head -c "$((scan_bytes + 1))" -- "$fd_path" | LC_ALL=C awk -v goal="$((start_line - 1))" '
                { n += length($0) + 1; if (NR >= goal) { print n; done=1; exit } }
                END { if (!done) print n+0 }')
            if [[ ! $start =~ ^[0-9]+$ ]]; then
                error "$p" OSError 'line-offset scan failed'
                exec {file_fd}<&-
                return
            fi
            if (( start > scan_bytes )); then
                error "$p" ValueError 'start_line scan exceeds 64 MiB; use byte_offset'
                exec {file_fd}<&-
                return
            fi
            (( start > before_size )) && start=$before_size
        fi
    fi
    if (( start > 0 )); then
        previous=$(dd if="$fd_path" iflag=nonblock,skip_bytes,count_bytes skip="$((start - 1))" count=1 status=none | base64 -w0)
    fi
    if ! data=$(dd if="$fd_path" iflag=nonblock,skip_bytes,count_bytes skip="$start" count="$count" status=none | base64 -w0); then
        error "$p" OSError 'bounded read failed'
    elif meta -L "$fd_path"; then
        emit R "$p" "$before_size" "$before_mtime" "$start" "$previous" "$data" "$size" "$mtime"
    else
        stat_error "$p"
    fi
    exec {file_fd}<&-
}

checksum() {
    local p=$1 before_size before_mtime output hash='' bytes='' line
    open_regular "$p" || return
    before_size=$size before_mtime=$mtime
    if (( size > max_file )); then
        error "$p" ValueError 'file exceeds max_file_bytes checksum limit'
        exec {file_fd}<&-
        return
    fi
    if ! output=$(exec 3>&1; head -c "$((max_file + 1))" -- "$fd_path" | tee >(wc -c >&3) | sha256sum); then
        error "$p" OSError 'checksum read failed'
        exec {file_fd}<&-
        return
    fi
    while IFS= read -r line; do
        if [[ $line =~ ^([[:xdigit:]]{64})[[:space:]] ]]; then hash=${BASH_REMATCH[1]}; fi
        if [[ $line =~ ^[[:space:]]*([0-9]+)[[:space:]]*$ ]]; then bytes=${BASH_REMATCH[1]}; fi
    done <<< "$output"
    if [[ -z $hash || -z $bytes ]]; then
        error "$p" OSError 'checksum collection failed'
    elif (( bytes > max_file )); then
        error "$p" ValueError 'file grew beyond checksum limit'
    elif meta -L "$fd_path"; then
        emit C "$p" "$hash" "$bytes" "$before_size" "$before_mtime" "$size" "$mtime"
    else
        stat_error "$p"
    fi
    exec {file_fd}<&-
}

grep_file() {
    local p=$1 rel=$2 raw kind number text flag rc=0 read_rc=0
    local -a args=(-I -n --no-group-separator)
    (( literal )) && args+=(-F) || args+=(-E)
    (( case_sensitive )) || args+=(-i)
    args+=(-C "$context_lines")
    open_regular "$p" || return
    if (( size > max_file )); then
        skipped_large=$((skipped_large + 1)); exec {file_fd}<&-; return
    fi
    scanned_bytes=$((scanned_bytes + size))
    if (( scanned_bytes > scan_bytes )); then
        scan_limited=1 stopped=1; exec {file_fd}<&-; return
    fi
    if binary; then skipped_binary=$((skipped_binary + 1)); exec {file_fd}<&-; return; fi
    while LC_ALL=C IFS= read -r -n 2097153 raw; do
        if [[ $raw == JMSFS_RC:* ]]; then read -r read_rc rc <<< "${raw#JMSFS_RC:}"; break; fi
        if (( ${#raw} >= 2097153 )); then
            error "$p" line_too_large 'search row exceeds 2 MiB; narrow the search'
            scan_limited=1 stopped=1; break
        fi
        if [[ $raw =~ ^([0-9]+)(:|-)(.*)$ ]]; then
            number=${BASH_REMATCH[1]} kind=${BASH_REMATCH[2]} text=${BASH_REMATCH[3]}
            [[ $kind == : ]] && kind=match || kind=context
            if accept; then
                flag=0; (( ${#text} > 8003 )) && flag=1
                emit L "$p" "$rel" "$number" "$kind" "${text:0:8003}" "$flag"
            fi
            (( stopped )) && break
        fi
    done < <(head -c "$max_file" -- "$fd_path" | grep "${args[@]}" -- "$pattern"; printf '\nJMSFS_RC:%s %s\n' "${PIPESTATUS[@]}")
    exec {file_fd}<&-
    if [[ $read_rc != 0 && $read_rc != 141 ]]; then error "$p" OSError 'search input read failed'; fi
    if [[ $rc != 0 && $rc != 1 && $rc != 141 ]]; then error "$p" grep_failed "grep failed (exit $rc); inspect probe stderr"; fi
}

walk() {
    local dir=$1 level=$2 name rel p status
    local -a names=()
    if [[ ! -r $dir || ! -x $dir ]]; then error "$dir" PermissionError 'cannot traverse directory'; return; fi
    while IFS= read -r -d '' name; do
        if [[ -z $name ]]; then
            IFS= read -r -d '' status
            [[ $status == 0 ]] || error "$dir" OSError 'directory enumeration failed; inspect probe stderr'
            break
        fi
        seen=$((seen + 1))
        if (( seen > scan_limit )); then scan_limited=1 stopped=1; return; fi
        names+=("$name")
    done < <(find -H "$dir" -mindepth 1 -maxdepth 1 -printf '%f\0'; printf '\0%s\0' "$?")
    (( ${#names[@]} )) || return
    while IFS= read -r -d '' name; do
        (( stopped )) && break
        if (( !hidden )) && [[ $name == .* ]]; then continue; fi
        p=${dir%/}/$name; rel=${p#"${root%/}/"}
        match_any "$rel" "${excludes[@]}" && continue
        if [[ $action == list || $action == tree ]]; then
            accept && info "$p" "$rel" "$level"
        elif [[ -f $p && ! -L $p ]] && selected "$rel"; then
            if [[ $action == glob ]]; then
                match_any "$rel" "$glob_pattern" && accept && info "$p" "$rel" "$level"
            else
                grep_file "$p" "$rel"
            fi
        fi
        if [[ -d $p && ! -L $p ]]; then
            if (( level < depth )); then walk "$p" "$((level + 1))";
            elif [[ $action == glob || $action == search ]]; then scan_limited=1 depth_limited=1; fi
        fi
    done < <(printf '%s\0' "${names[@]}" | LC_ALL=C sort -z)
}

rg_search() {
    local raw rc=0
    (( ${#batch[@]} )) || return
    while LC_ALL=C IFS= read -r -n 2097153 raw; do
        if [[ $raw == JMSFS_RC:* ]]; then rc=${raw#JMSFS_RC:}; break; fi
        if (( ${#raw} >= 2097153 )); then
            error "$root" line_too_large 'rg JSON event exceeds 2 MiB; narrow the search'
            scan_limited=1 stopped=1; break
        fi
        if [[ $raw =~ \"type\"[[:space:]]*:[[:space:]]*\"(match|context)\" ]]; then
            accept && emit J "$raw"
            (( stopped )) && break
        fi
    done < <("$rg_bin" "${rg_query[@]}" -- "$pattern" "${batch[@]}"; printf '\nJMSFS_RC:%s\n' "$?")
    if [[ $rc != 0 && $rc != 1 && $rc != 141 ]]; then error "$root" ripgrep_failed "ripgrep failed (exit $rc); inspect probe stderr"; fi
    batch=()
}

rg_files() {
    local rel p status
    local -a file_args=(--no-config --files --null --sort path --threads 1)
    (( hidden )) && file_args+=(--hidden)
    (( respect_ignore )) || file_args+=(--no-ignore)
    # Exclude patterns are also applied by the explicit matcher after discovery.
    while IFS= read -r -d '' rel; do
        if [[ -z $rel ]]; then
            IFS= read -r -d '' status
            [[ $status == 0 || $status == 1 ]] || error "$root" ripgrep_failed 'ripgrep file discovery failed; inspect probe stderr'
            break
        fi
        seen=$((seen + 1)); if (( seen > scan_limit )); then scan_limited=1 stopped=1; break; fi
        rel=${rel#./}; p=${root%/}/$rel
        match_any "$rel" "${excludes[@]}" && continue
        # Excluding a directory must exclude its descendants, including basename matches.
        excluded_ancestor "$rel" && continue
        selected "$rel" || continue
        if [[ $action == glob ]]; then
            match_any "$rel" "$glob_pattern" && accept && emit G "$p" "$rel"
        else
            batch+=("$p")
            (( ${#batch[@]} >= 32 )) && rg_search
        fi
        (( stopped )) && break
    done < <(cd -- "$root" && { "$rg_bin" "${file_args[@]}" -- .; printf '\0%s\0' "$?"; })
    [[ $action == search && $stopped == 0 ]] && rg_search
}

excluded_ancestor() {
    local value=$1
    while [[ $value == */* ]]; do
        value=${value%/*}
        match_any "$value" "${excludes[@]}" && return 0
    done
    return 1
}

main() {
    local cmd p warning='' rc
    local -a required=(stat)
    if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 2) )); then
        error "$root" UnsupportedOperation 'filesystem backend requires Bash 4.2+'
        return
    fi
    case $action in
        read|read_many) required+=(dd head od grep awk);;
        checksum) required+=(head tee wc sha256sum);;
        stat) required+=(readlink);;
        list|tree|glob) required+=(find sort readlink grep);;
        search) required+=(find sort readlink grep head od);;
        *) error "$root" ValueError 'unsupported filesystem action'; return;;
    esac
    for cmd in "${required[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then error "$root" UnsupportedOperation "missing target command: $cmd"; return; fi
    done
    if [[ $action == glob || $action == search ]]; then
        rg_bin=$(command -v -- "$rg_command" 2>/dev/null || command -v rg 2>/dev/null)
        if [[ -n $rg_bin ]]; then
            engine=ripgrep ignore_applied=$respect_ignore skipped_large=-1 skipped_binary=-1
        else
            [[ $action == search ]] && engine=grep
            (( respect_ignore )) && warning='rg unavailable: .gitignore/.ignore rules are not applied; use exclude or install rg.'
        fi
    fi
    emit H "$engine" "$ignore_applied" "$warning"
    case $action in
        stat) info "$root" '' 0;;
        read) read_file "$root" "$budget";;
        read_many) for p in "${paths[@]}"; do read_file "$p" "$((budget / ${#paths[@]}))"; done;;
        checksum) checksum "$root";;
        list|tree|glob|search)
            if [[ $action == search ]]; then
                if [[ $engine == ripgrep ]]; then
                    rg_query=(--no-config --json --color never --sort path --threads 1 --max-filesize "$max_file" --context "$context_lines")
                    (( literal )) && rg_query+=(--fixed-strings)
                    (( case_sensitive )) || rg_query+=(--ignore-case)
                    "$rg_bin" "${rg_query[@]}" -- "$pattern" /dev/null >/dev/null; rc=$?
                else
                    if (( !literal )) && [[ $pattern == *'\d'* || $pattern == *'\D'* || $pattern == *'\A'* || $pattern == *'\Z'* || $pattern == *'(?'* ]]; then
                        error "$root" UnsupportedPattern 'grep fallback uses POSIX ERE; use character classes such as [[:digit:]]'
                        return
                    fi
                    local -a validation=(-I -n -E)
                    (( literal )) && validation=(-I -n -F)
                    grep "${validation[@]}" -- "$pattern" /dev/null >/dev/null; rc=$?
                fi
                if [[ $rc != 0 && $rc != 1 ]]; then
                    error "$root" "${engine}_failed" 'invalid search pattern; inspect probe stderr'
                    return
                fi
            fi
            if [[ -d $root ]]; then
                if [[ $engine == ripgrep ]]; then batch=(); rg_files; else walk "$root" 1; fi
            elif [[ $action == search && -f $root ]]; then
                if [[ $engine == ripgrep ]]; then batch=("$root"); rg_search; else grep_file "$root" "${root##*/}"; fi
            else
                error "$root" ValueError 'list/tree/glob require a directory; search requires an existing file or directory'
            fi;;
    esac
}

main
printf 'P\0%s\0%s\0%s\0%s\0%s\0%s\0%s\0' "$seen" "$skipped_large" "$skipped_binary" "$scan_limited" "$depth_limited" "$started" "${EPOCHREALTIME:-$SECONDS}"
