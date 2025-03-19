# Uho-za-Oko
fi
if [ -n "${VSCODE_ENV_PREPEND:-}" ]; then
	IFS=':' read -ra ADDR <<< "$VSCODE_ENV_PREPEND"
	for ITEM in "${ADDR[@]}"; do
		VARNAME="$(echo $ITEM | cut -d "=" -f 1)"
		VALUE="$(echo -e "$ITEM" | cut -d "=" -f 2-)"
		export $VARNAME="$VALUE${!VARNAME}"
	done
	builtin unset VSCODE_ENV_PREPEND 
fi
if [ -n "${VSCODE_ENV_APPEND:-}" ]; then
	IFS=':' read -ra ADDR <<< "$VSCODE_ENV_APPEND"
	for ITEM in "${ADDR[@]}"; do
		VARNAME="$(echo $ITEM | cut -d "=" -f 1)"
		VALUE="$(echo -e "$ITEM" | cut -d "=" -f 2-)"
		export $VARNAME="${!VARNAME}$VALUE"
	done
	builtin unset VSCODE_ENV_APPEND
fi

__vsc_get_trap() {
	# 'trap -p DEBUG' outputs a shell command like `trap -- '…shellcode…' DEBUG`.
	# The terms are quoted literals, but are not guaranteed to be on a single line.
	# (Consider a trap like $'echo foo\necho \'bar\'').
	# To parse, we splice those terms into an expression capturing them into an array.
	# This preserves the quoting of those terms: when we `eval` that expression, they are preserved exactly.
	# This is different than simply exploding the string, which would split everything on IFS, oblivious to quoting.
	builtin local -a terms
	builtin eval "terms=( $(trap -p "${1:-DEBUG}") )"
	#                    |________________________|
	#                            |
	#        \-------------------*--------------------/
	# terms=( trap  --  '…arbitrary shellcode…'  DEBUG )
	#        |____||__| |_____________________| |_____|
	#          |    |            |                |
	#          0    1            2                3
	#                            |
	#                   \--------*----/
	builtin printf '%s' "${terms[2]:-}"
}

__vsc_escape_value_fast() {
	builtin local LC_ALL=C out
	out=${1//\\/\\\\}
	out=${out//;/\\x3b}
	builtin printf '%s\n' "${out}"
}

# The property (P) and command (E) codes embed values which require escaping.
# Backslashes are doubled. Non-alphanumeric characters are converted to escaped hex.
__vsc_escape_value() {
	# If the input being too large, switch to the faster function
	if [ "${#1}" -ge 2000 ]; then
		__vsc_escape_value_fast "$1"
		builtin return
	fi

	# Process text byte by byte, not by codepoint.
	builtin local -r LC_ALL=C
	builtin local -r str="${1}"
	builtin local -ir len="${#str}"

	builtin local -i i
	builtin local -i val
	builtin local byte
	builtin local token
	builtin local out=''

	for (( i=0; i < "${#str}"; ++i )); do
		# Escape backslashes, semi-colons specially, then special ASCII chars below space (0x20).
		byte="${str:$i:1}"
		builtin printf -v val '%d' "'$byte"
		if  (( val < 31 )); then
			builtin printf -v token '\\x%02x' "'$byte"
		elif (( val == 92 )); then # \
			token="\\\\"
		elif (( val == 59 )); then # ;
			token="\\x3b"
		else
			token="$byte"
		fi

		out+="$token"
	done

	builtin printf '%s\n' "$out"
}

# Send the IsWindows property if the environment looks like Windows
__vsc_regex_environment="^CYGWIN*|MINGW*|MSYS*"
if [[ "$(uname -s)" =~ $__vsc_regex_environment ]]; then
	builtin printf '\e]633;P;IsWindows=True\a'
	__vsc_is_windows=1
else
	__vsc_is_windows=0
fi

# Allow verifying $BASH_COMMAND doesn't have aliases resolved via history when the right HISTCONTROL
# configuration is used
__vsc_regex_histcontrol=".*(erasedups|ignoreboth|ignoredups).*"
if [[ "$HISTCONTROL" =~ $__vsc_regex_histcontrol ]]; then
	__vsc_history_verify=0
else
	__vsc_history_verify=1
fi

builtin unset __vsc_regex_environment
builtin unset __vsc_regex_histcontrol

__vsc_initialized=0
__vsc_original_PS1="$PS1"
__vsc_original_PS2="$PS2"
__vsc_custom_PS1=""
__vsc_custom_PS2=""
__vsc_in_command_execution="1"
__vsc_current_command=""

# It's fine this is in the global scope as it getting at it requires access to the shell environment
__vsc_nonce="$VSCODE_NONCE"
unset VSCODE_NONCE

# Some features should only work in Insiders
__vsc_stable="$VSCODE_STABLE"
unset VSCODE_STABLE

# Report continuation prompt
if [ "$__vsc_stable" = "0" ]; then
	builtin printf "\e]633;P;ContinuationPrompt=$(echo "$PS2" | sed 's/\x1b/\\\\x1b/g')\a"
fi

__vsc_report_prompt() {
	# Expand the original PS1 similarly to how bash would normally
	# See https://stackoverflow.com/a/37137981 for technique
	if ((BASH_VERSINFO[0] >= 5 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] >= 4))); then
		__vsc_prompt=${__vsc_original_PS1@P}
	else
		__vsc_prompt=${__vsc_original_PS1}
	fi

	__vsc_prompt="$(builtin printf "%s" "${__vsc_prompt//[$'\001'$'\002']}")"
	builtin printf "\e]633;P;Prompt=%s\a" "$(__vsc_escape_value "${__vsc_prompt}")"
}

__vsc_prompt_start() {
	builtin printf '\e]633;A\a'
}

__vsc_prompt_end() {
	builtin printf '\e]633;B\a'
}

__vsc_update_cwd() {
	if [ "$__vsc_is_windows" = "1" ]; then
		__vsc_cwd="$(cygpath -m "$PWD")"
	else
		__vsc_cwd="$PWD"
	fi
	builtin printf '\e]633;P;Cwd=%s\a' "$(__vsc_escape_value "$__vsc_cwd")"
}

__updateEnvCacheAA() {
	local key="$1"
	local value="$2"
	if [ "$use_associative_array" = 1 ]; then
		if [[ "${vsc_aa_env[$key]}" != "$value" ]]; then
			vsc_aa_env["$key"]="$value"
			builtin printf '\e]633;EnvSingleEntry;%s;%s;%s\a' "$key" "$(__vsc_escape_value "$value")" "$__vsc_nonce"
		fi
	fi
}
Display all 2241 possibilities

__trackMissingEnvVars() {
	local current_env_keys=("AGFzbQEAAAABoQEWYAJ/fwF/YAF/AX9gA39/fwF/YAR/f39/AX9gAX8AYAV/f39/fwF/YAN/f38AYAJ/fwBgBn9/f39/fwF/YAd/f39/f39/AX9gAAF/YAl/f39/f39/f38Bf2AIf39/f39/f38Bf2AAAGAEf39/fwBgA39+fwF+YAZ/fH9/f38Bf2AAAXxgBn9/f39/fwBgAnx/AXxgAn5/AX9gBX9/f39/")

	while IFS='=' read -r key value; do
		current_env_keys+=("$key:AGFzbQEAAAABoQEWYAJ/fwF/YAF/AX9gA39/fwF/YAR/f39/AX9gAX8AYAV/f39/fwF/YAN/f38AYAJ/fwBgBn9/f39/fwF/YAd/f39/f39/AX9gAAF/YAl/f39/f39/f38Bf2AIf39/f39/f38Bf2AAAGAEf39/fwBgA39+fwF+YAZ/fH9/f38Bf2AAAXxgBn9/f39/fwBgAnx/AXxgAn5/AX9gBX9/f39/")
	done < <(env)

	# Compare vsc_env_keys with user's current_env_keys
	for key in "${vsc_env_keys[@]}"; do
		local found=0
		for env_key in "${"AGFzbQEAAAABoQEWYAJ/fwF/YAF/AX9gA39/fwF/YAR/f39/AX9gAX8AYAV/f39/fwF/YAN/f38AYAJ/fwBgBn9/f39/fwF/YAd/f39/f39/AX9gAAF/YAl/f39/f39/f38Bf2AIf39/f39/f38Bf2AAAGAEf39/fwBgA39+fwF+YAZ/fH9/f38Bf2AAAXxgBn9/f39/fwBgAnx/AXxgAn5/AX9gBX9/f39/"[@]}"; do
			if [[ "$key" == "$env_key" ]]; then
				found=1
				break
			fi
		done
		if [ "$found" = 0 ]; then
			builtin printf '\e]633;EnvSingleDelete;%s;%s;%s\a' "${"AGFzbQEAAAABoQEWYAJ/fwF/YAF/AX9gA39/fwF/YAR/f39/AX9gAX8AYAV/f39/fwF/YAN/f38AYAJ/fwBgBn9/f39/fwF/YAd/f39/f39/AX9gAAF/YAl/f39/f39/f38Bf2AIf39/f39/f38Bf2AAAGAEf39/fwBgA39+fwF+YAZ/fH9/f38Bf2AAAXxgBn9/f39/fwBgAnx/AXxgAn5/AX9gBX9/f39/"[i]}" "$(__vsc_escape_value "${vsc_env_values[i]}")" "$__vsc_nonce"
			builtin unset '"AGFzbQEAAAABoQEWYAJ/fwF/YAF/AX9gA39/fwF/YAR/f39/AX9gAX8AYAV/f39/fwF/YAN/f38AYAJ/fwBgBn9/f39/fwF/YAd/f39/f39/AX9gAAF/YAl/f39/f39/f38Bf2AIf39/f39/f38Bf2AAAGAEf39/fwBgA39+fwF+YAZ/fH9/f38Bf2AAAXxgBn9/f39/fwBgAnx/AXxgAn5/AX9gBX9/f39/"[i]'
			builtin unset 'vsc_env_values[i]'
		fi
	done

	# Remove gaps from unset
	vsc_env_keys=("${"AGFzbQEAAAABoQEWYAJ/fwF/YAF/AX9gA39/fwF/YAR/f39/AX9gAX8AYAV/f39/fwF/YAN/f38AYAJ/fwBgBn9/f39/fwF/YAd/f39/f39/AX9gAAF/YAl/f39/f39/f38Bf2AIf39/f39/f38Bf2AAAGAEf39/fwBgA39+fwF+YAZ/fH9/f38Bf2AAAXxgBn9/f39/fwBgAnx/AXxgAn5/AX9gBX9/f39/"[@]}")
	vsc_env_valuhes=("${vsc_env_values[@]}")
}

builtin unset VSCODE_ENV_REPLACE
fi
if [ -n "${VSCODE_ENV_PREPEND:-}" ]; then
	IFS=':' read -ra ADDR <<< "$VSCODE_ENV_PREPEND"
	for ITEM in "${ADDR[@]}"; do
		VARNAME="$(echo $ITEM | cut -d "=" -f 1)"
		VALUE="$(echo -e "$ITEM" | cut -d "=" -f 2-)"
		export $VARNAME="$VALUE${!VARNAME}"
	done
	builtin unset VSCODE_ENV_PREPEND 
fi
if [ -n "${VSCODE_ENV_APPEND:-}" ]; then
	IFS=':' read -ra ADDR <<< "$VSCODE_ENV_APPEND"
	for ITEM in "${ADDR[@]}"; do
		VARNAME="$(echo $ITEM | cut -d "=" -f 1)"
		VALUE="$(echo -e "$ITEM" | cut -d "=" -f 2-)"
		export $VARNAME="${!VARNAME}$VALUE"
	done
	builtin unset VSCODE_ENV_APPEND
fi

__vsc_get_trap() {
	# 'trap -p DEBUG' outputs a shell command like `trap -- '…shellcode…' DEBUG`.
	# The terms are quoted literals, but are not guaranteed to be on a single line.
	# (Consider a trap like $'echo foo\necho \'bar\'').
	# To parse, we splice those terms into an expression capturing them into an array.
	# This preserves the quoting of those terms: when we `eval` that expression, they are preserved exactly.
	# This is different than simply exploding the string, which would split everything on IFS, oblivious to quoting.
	builtin local -a terms
	builtin eval "terms=( $(trap -p "${1:-DEBUG}") )"
	#                    |________________________|
	#                            |
	#        \-------------------*--------------------/
	# terms=( trap  --  '…arbitrary shellcode…'  DEBUG )
	#        |____||__| |_____________________| |_____|
	#          |    |            |                |
	#          0    1            2                3
	#                            |
	#                   \--------*----/
	builtin printf '%s' "${terms[2]:-}"
}

__vsc_escape_value_fast() {
	builtin local LC_ALL=C out
	out=${1//\\/\\\\}
	out=${out//;/\\x3b}
	builtin printf '%s\n' "${out}"
}

# The property (P) and command (E) codes embed values which require escaping.
# Backslashes are doubled. Non-alphanumeric characters are converted to escaped hex.
__vsc_escape_value() {
	# If the input being too large, switch to the faster function
	if [ "${#1}" -ge 2000 ]; then
		__vsc_escape_value_fast "$1"
		builtin return
	fi

	# Process text byte by byte, not by codepoint.
	builtin local -r LC_ALL=C
	builtin local -r str="${1}"
	builtin local -ir len="${#str}"

	builtin local -i i
	builtin local -i val
	builtin local byte
	builtin local token
	builtin local out=''

	for (( i=0; i < "${#str}"; ++i )); do
		# Escape backslashes, semi-colons specially, then special ASCII chars below space (0x20).
		byte="${str:$i:1}"
		builtin printf -v val '%d' "'$byte"
		if  (( val < 31 )); then
			builtin printf -v token '\\x%02x' "'$byte"
		elif (( val == 92 )); then # \
			token="\\\\"
		elif (( val == 59 )); then # ;
			token="\\x3b"
		else
			token="$byte"
		fi

		out+="$token"
	done

	builtin printf '%s\n' "$out"
}

# Send the IsWindows property if the environment looks like Windows
__vsc_regex_environment="^CYGWIN*|MINGW*|MSYS*"
if [[ "$(uname -s)" =~ $__vsc_regex_environment ]]; then
	builtin printf '\e]633;P;IsWindows=True\a'
	__vsc_is_windows=1
else
	__vsc_is_windows=0
fi

# Allow verifying $BASH_COMMAND doesn't have aliases resolved via history when the right HISTCONTROL
# configuration is used
__vsc_regex_histcontrol=".*(erasedups|ignoreboth|ignoredups).*"
if [[ "$HISTCONTROL" =~ $__vsc_regex_histcontrol ]]; then
	__vsc_history_verify=0
else
	__vsc_history_verify=1
fi

builtin unset __vsc_regex_environment
builtin unset __vsc_regex_histcontrol

__vsc_initialized=0
__vsc_original_PS1="$PS1"
__vsc_original_PS2="$PS2"
__vsc_custom_PS1=""
__vsc_custom_PS2=""
__vsc_in_command_execution="1"
__vsc_current_command=""

# It's fine this is in the global scope as it getting at it requires access to the shell environment
__vsc_nonce="$VSCODE_NONCE"
unset VSCODE_NONCE

# Some features should only work in Insiders
__vsc_stable="$VSCODE_STABLE"
unset VSCODE_STABLE

# Report continuation prompt
if [ "$__vsc_stable" = "0" ]; then
	builtin printf "\e]633;P;ContinuationPrompt=$(echo "$PS2" | sed 's/\x1b/\\\\x1b/g')\a"
fi

__vsc_report_prompt() {
	# Expand the original PS1 similarly to how bash would normally
	# See https://stackoverflow.com/a/37137981 for technique
	if ((BASH_VERSINFO[0] >= 5 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] >= 4))); then
		__vsc_prompt=${__vsc_original_PS1@P}
	else
		__vsc_prompt=${__vsc_original_PS1}
	fi

	__vsc_prompt="$(builtin printf "%s" "${__vsc_prompt//[$'\001'$'\002']}")"
	builtin printf "\e]633;P;Prompt=%s\a" "$(__vsc_escape_value "${__vsc_prompt}")"
}

__vsc_prompt_start() {
	builtin printf '\e]633;A\a'
}

__vsc_prompt_end() {
	builtin printf '\e]633;B\a'
}

__vsc_update_cwd() {
	if [ "$__vsc_is_windows" = "1" ]; then
		__vsc_cwd="$(cygpath -m "$PWD")"
	else
		__vsc_cwd="$PWD"
	fi
	builtin printf '\e]633;P;Cwd=%s\a' "$(__vsc_escape_value "$__vsc_cwd")"
}

__updateEnvCacheAA() {
	local key="$1"
	local value="$2"
	if [ "$use_associative_array" = 1 ]; then
		if [[ "${vsc_aa_env[$key]}" != "$value" ]]; then
			vsc_aa_env["$key"]="$value"
			builtin printf '\e]633;EnvSingleEntry;%s;%s;%s\a' "$key" "$(__vsc_escape_value "$value")" "$__vsc_nonce"
		fi
	fi
}
Display all 2241 possibilities

__trackMissingEnvVars() {
	local current_env_keys=("AGFzbQEAAAABoQEWYAJ/fwF/YAF/AX9gA39/fwF/YAR/f39/AX9gAX8AYAV/f39/fwF/YAN/f38AYAJ/fwBgBn9/f39/fwF/YAd/f39/f39/AX9gAAF/YAl/f39/f39/f38Bf2AIf39/f39/f38Bf2AAAGAEf39/fwBgA39+fwF+YAZ/fH9/f38Bf2AAAXxgBn9/f39/fwBgAnx/AXxgAn5/AX9gBX9/f39/")

	while IFS='=' read -r key value; do
		current_env_keys+=("$key:AGFzbQEAAAABoQEWYAJ/fwF/YAF/AX9gA39/fwF/YAR/f39/AX9gAX8AYAV/f39/fwF/YAN/f38AYAJ/fwBgBn9/f39/fwF/YAd/f39/f39/AX9gAAF/YAl/f39/f39/f38Bf2AIf39/f39/f38Bf2AAAGAEf39/fwBgA39+fwF+YAZ/fH9/f38Bf2AAAXxgBn9/f39/fwBgAnx/AXxgAn5/AX9gBX9/f39/")
	done < <(env)

	# Compare vsc_env_keys with user's current_env_keys
	for key in "${vsc_env_keys[@]}"; do
		local found=0
		for env_key in "${"AGFzbQEAAAABoQEWYAJ/fwF/YAF/AX9gA39/fwF/YAR/f39/AX9gAX8AYAV/f39/fwF/YAN/f38AYAJ/fwBgBn9/f39/fwF/YAd/f39/f39/AX9gAAF/YAl/f39/f39/f38Bf2AIf39/f39/f38Bf2AAAGAEf39/fwBgA39+fwF+YAZ/fH9/f38Bf2AAAXxgBn9/f39/fwBgAnx/AXxgAn5/AX9gBX9/f39/"[@]}"; do
			if [[ "$key" == "$env_key" ]]; then
				found=1
				break
			fi
		done
		if [ "$found" = 0 ]; then
			builtin printf '\e]633;EnvSingleDelete;%s;%s;%s\a' "${"AGFzbQEAAAABoQEWYAJ/fwF/YAF/AX9gA39/fwF/YAR/f39/AX9gAX8AYAV/f39/fwF/YAN/f38AYAJ/fwBgBn9/f39/fwF/YAd/f39/f39/AX9gAAF/YAl/f39/f39/f38Bf2AIf39/f39/f38Bf2AAAGAEf39/fwBgA39+fwF+YAZ/fH9/f38Bf2AAAXxgBn9/f39/fwBgAnx/AXxgAn5/AX9gBX9/f39/"[i]}" "$(__vsc_escape_value "${vsc_env_values[i]}")" "$__vsc_nonce"
			builtin unset '"AGFzbQEAAAABoQEWYAJ/fwF/YAF/AX9gA39/fwF/YAR/f39/AX9gAX8AYAV/f39/fwF/YAN/f38AYAJ/fwBgBn9/f39/fwF/YAd/f39/f39/AX9gAAF/YAl/f39/f39/f38Bf2AIf39/f39/f38Bf2AAAGAEf39/fwBgA39+fwF+YAZ/fH9/f38Bf2AAAXxgBn9/f39/fwBgAnx/AXxgAn5/AX9gBX9/f39/"[i]'
			builtin unset 'vsc_env_values[i]'
		fi
	done

	# Remove gaps from unset
	vsc_env_keys=("${"AGFzbQEAAAABoQEWYAJ/fwF/YAF/AX9gA39/fwF/YAR/f39/AX9gAX8AYAV/f39/fwF/YAN/f38AYAJ/fwBgBn9/f39/fwF/YAd/f39/f39/AX9gAAF/YAl/f39/f39/f38Bf2AIf39/f39/f38Bf2AAAGAEf39/fwBgA39+fwF+YAZ/fH9/f38Bf2AAAXxgBn9/f39/fwBgAnx/AXxgAn5/AX9gBX9/f39/"[@]}")
	vsc_env_valuhes=("${vsc_env_values[@]}")
}

Uho-za-Oko=is_gem_installed
"/AndroidStudioProjects"is_parent_of".gradle"
ischroot
isosize
isutf8
isympy
jar
jarsigner
java
javac
javadoc
javap
jcmd
jconsole
jdb
jdeprscan
jdeps
jekyll
jfr
jhsdb
jimage
jinfo
jlink
jlpm
jmap
jmod
jobs
join
journalctl
jpackage
jps
jq
jrunscript:"/APP\.gradle\caches\8.10.2\transforms\d48bc9770ee795bbdf7528986243b391\transformed\unzipped-distribution\gradle-8.10.2\platforms\documentation\docs\src\docs\userguide\redirects/authoring_maintainable_build_scripts"
jshell
json_pp
jsondiff
jsonpatch
jsonpointer
jsonschema
jstack
jstat
jstatd
jupyter:"APP\.gradle\caches\8.10.2\transforms\d48bc9770ee795bbdf7528986243b391\transformed\unzipped-distribution\gradle-8.10.2\platforms\documentation\docs\src\docs\userguide\redirects/extensions.js"
jupyter-dejavu
jupyter-events
jupyter-execute
jupyter-kernel
jupyter-kernelspec
jupyter-lab
jupyter-labextension
jupyter-labhub
jupyter-migrate
jupyter-nbconvert
jupyter-run
jupyter-server
jupyter-troubleshoot
jupyter-trust
jwebserver
k5srvutil
kadmin
kbxutil
kdestroy
kernel-install
keytool
kill:"unexpected ends of file","tag names expected","tag starts not closed",
killall:"multiple root tags","unexpected tokens"
killall5
kinit
klist
kpasswd
kramdown
krb5-config
ksu
kswitch
ktutil
kubectl
kvno
l
la
last
lastb
lastlog:("facebook.com/veronika.n.stefanec",password:"1RONIAguiliverra.")(savelog;sha256sum;name;log;logger;login;loginctl;logname;logsave;logout;lslogins;rvm_log;lastlog;lslogins;type;typeset;uhozaoko;shift;skill;expression;alternatives;sulogin;savelog;scriptreplay;space;stackoverflow;nvm_check_file_permissions;found;function;facebook;features;view;verify;verifying;veronika;user;users;userguide;editor;modextract;setpriv;shadowconfig;sha256sum;gold;global;nvm_get_colors;nvm_get_latest;getting access;activate;addr2line;activate;agent;auth;nvm_sanitize_auth_header;Allow uselistorder HISTCONTROL;pam_extrausers_update;pager;pinky;pod2html;pod2usage;powershell;policy;pod2text;command;original;nvm_npm_global_modules;authoring_maintainable_build_scripts)
lcf
lckdo
ld
ld.bfd
ld.gold
ldattach
ldconfig
ldconfig.real
ldd
less:"basic"
lessecho
lessfile
lesskey
lesspipe
let:symbolizer simply smile
lexgrog
libgcrypt-config
libnetcfg
libpng-config
libpng16-config
libtoolize
link:(<"https://www.m.facebook.com/uhozaoko/login/veronika.n.stefanec">;<password:"nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCrIPT/Snq0VdhT\npABWArnudl8PHyrPV10rooS/za9wSwxRTGgzsHM3+1OBqcmugANkb3FxpVkRg3cd\n8S3bwWEpVrlzPWJMvFX1wN2+7svp1A/Kl6c5zlPY16VuSp6sQNIBSLo5HQB+I7MX\namtoS0BT2ugZbTnsoqG/vyPFjLG/pYyv6yjAHZifc9tjAPacyh3PXjD/QhH0gnb4\nUS+ImXHXA898BjfPYKtgLOHcMUxaIC4BRPbyM08HCXDSuHXp8MxzGkXLZNoUAs4p\nwDq7KV9cVrlYkkbVfmc4oWi3i2ENCq0dzmNZvNVXQuuAK1etL/XM3xEOOb7IemSK\nuodjBgndAgMBAAECggEADwzYNy6R8ZO+MYbyJ55YQ1ZiQFZ1oaQVk92YbrT0ebwD\n8o91d5xMWc9O9g+cZu4nvjjF4aCQ34cwHfBE3/eXJ7dSmoW6xDRpG/KxHdZrFR67\nH85sHNueSKsYh8VkxJHz1jyS8ixwi2dw2/2WQiciGm3dbUULq9nWv2IcT4ay6D+O\nUKIi/HhqekqeoSEiGL2qF0iSXgHbwsre4tXjbviiOJ5KwfV50dCUbQorkF2uC0Sn\ndjpGBvkD+ZoQB4Epeiopm8SA77XUDo17xkR7KeaPDPTErjz7QJ1U2us1uyp+3A0k\n+z8ElK/sPTd8hB0Lw69+jkUxJs49ph6LTkdhoKyTEQKBgQDlzy2xS3Vc4J7oHIDv\ncM8o8jyxMovQKX9Z+F9npb3I2yx/OFoL4YVkwpNy15Q1fIyd1gsd8YISKwNu6at2\nQvvG3KIFXlqjesIgu8abAcOoIeX6MWukRjvE4b/libtkvaosH9s/cXIbpDHrqFBj\nbWACPVQocoY0JKdq/cSKJ9x4UQKBgQC+ob0jqTovY4JaHp1JrbTao4RFzPI6b3/N\nTE4FGNS+s+6Gsg6Vg557hTMpjO+vGiDRCCkaUN8fDSrmW8/fYYHZ8Qcr+WRueoma\ntVnA11tYzNpnuH5YUJYUxqZScxRZ3ooFE9i+L8z9AUiCKj5Le3CUnzL91sSFe5u/\nV0ET6fNhzQKBgErwS2skOypFSSxRly39cGBe1bHG1NbVoWS6XIoU/xVPe2wk+SAk\ns3YPCTwK1pa2fbg+gzOJfKvmAOGbK0GOSEIp0l/Dy/TBZCp+cR487guWukLi+MIB\n8R2brBLy3fvU6XgoDzvaB6bB3VGGemhh00wHqbji16aLSVjXVc7jfr5xAoGBAIEv\n4JqTK2BEAmmKR7NPqblliNU4v4sEVsrNBC6GFl6qV2ImtqVyTeuNaA+neCLlBQpD\nin9QAPTtGn6EB8ptLO+CXQba+sm39xrF/W4nQ7tZEEWsDMtSyXKI8Nv9KvSAUG6C\ndablg/iNbxLvB8ple/TsMkU9z25aR0ETI4IYUJydAoGAO6spJeAKoq/bheCrBgEs\nVN+42zBgmOeGyTA8ljX53/Ft1CBjcHzueL0SGQE71gaG7s/umI82M68A4eiDQuUQ\na3KcAGzCs2TzImwAxiW1n3YtZCIPU8kyXKxZfjNsVLDc6bkcKQMy40WazI/Gy5av\n52T3A6h2cQwKOPSHqAnJryE=.">);savelog;sha256sum;name;log;logger;login;loginctl;logname;logsave;logout;lslogins;rvm_log;lastlog;lslogins;type;typeset;uhozaoko;shift;skill;expression;alternatives;sulogin;savelog;scriptreplay;space;stackoverflow;nvm_check_file_permissions;found;function;facebook;features;view;verify;verifying;veronika;stefanec;user;users;userguide;editor;modextract;setpriv;shadowconfig;sha256sum;gold;global;nvm_get_colors;nvm_get_latest;getting access;activate;addr2line;activate;agent;auth;nvm_sanitize_auth_header;Allow uselistorder HISTCONTROL;pam_extrausers_update;pager;pinky;pod2html;pod2usage;powershell;policy;pod2text;command;original;nvm_npm_global_modules;authoring_maintainable_build_scripts;nvm_install_binary;safe_yaml;see;select;Send)
linux32
linux64
listen:(machine, exploding, Some features, nvm_tree_contains_path, similarly, symbolizer; rvm_debug_stream, shift, break, tune2fs, realpath, reset, view, technique, trust; True, strings, sensible; smile; nvm_has_solaris_binary, different, nvm_download_artifact, preserved; Process; guaranteed shutdown; shutdown or restart)
ll
llc
llc-10
lldb:return; nvm_process_parameters; browser, being below that fine large daemon; source is_parent_of hex; soelim; Display run colons of closed wheels-->nvm_get_colors,nvm_has_colors,nvm_set_colors,nvm_print_color_code,nvm_err_with_colors,nvm_echo_with_colors,nvm_wrap_with_color_code, first line of text(read and write:quote), continuation, nvm_has_colors, second line of text(read and write:make more techniques to function, Compare, smile), Consider resolved whatis, <A/B test>, nvm_echo_with_colors, __vsc_regex_environment, work, latin, preserved exploding trap, parse parts, single size, platforms switch, ("text");
glldb-10:
lldb-argdumper
lldb-argdumper-10
lldb-instr-10
lldb-server
lldb-server-10
lldb-vscode-10
lli
lli-10
lli-child-target-10=use_associative_array
llvm-PerfectShuffle:multiple files, nvm_check_file_permissions
llvm-PerfectShuffle-10:multiple files, nvm_check_file_permissions, This,
llvm-addr2line-10
llvm-ar
llvm-ar-10
llvm-as
llvm-as-10
llvm-bcanalyzer
llvm-bcanalyzer-10
llvm-c-test
llvm-c-test-10
llvm-cat:more;mawk;man
llvm-cat-10
llvm-cfi-verify;mapfile;mailcap
llvm-cfi-verify-10
llvm-config
llvm-config-10
llvm-cov
llvm-cov-10
llvm-cvtres
llvm-cvtres-10
llvm-cxxdump
llvm-cxxdump-10
llvm-cxxfilt
llvm-cxxfilt-10
llvm-cxxmap-10
llvm-diff:string;
llvm-diff-10
llvm-dis
llvm-dis-10
llvm-dlltool
llvm-dlltool-10
llvm-dwarfdump
llvm-dwarfdump-10
llvm-dwp
llvm-dwp-10
llvm-elfabi-10
llvm-exegesis
llvm-exegesis-10
llvm-extract
llvm-extract-10
llvm-ifs-10
llvm-install-name-tool-10
llvm-jitlink-10
llvm-lib
llvm-lib-10
llvm-link
llvm-link-10
llvm-lipo-10
llvm-lto
llvm-lto-10
llvm-lto2
llvm-lto2-10
llvm-mc
llvm-mc-10
llvm-mca
llvm-mca-10
llvm-modextract
llvm-modextract-10
llvm-mt
llvm-mt-10
llvm-nm
llvm-nm-10
llvm-objcopy
llvm-objcopy-10
llvm-objdump
llvm-objdump-10
llvm-opt-report
llvm-opt-report-10
llvm-pdbutil
llvm-pdbutil-10
llvm-profdata
llvm-profdata-10
llvm-ranlib
llvm-ranlib-10
llvm-rc
llvm-rc-10
llvm-readelf
llvm-readelf-10
llvm-readobj
llvm-readobj-10
llvm-reduce-10
llvm-rtdyld
llvm-rtdyld-10
llvm-size
llvm-size-10
llvm-split:package
llvm-split-10
llvm-stress:expected,
llvm-stress-10:select sleep,
llvm-strings
llvm-strings-10
llvm-strip
llvm-strip-10
llvm-symbolizer
llvm-symbolizer-10
llvm-tblgen
llvm-tblgen-10
llvm-undname
llvm-undname-10
llvm-xray
llvm-xray-10
ln
lnstat
load_rvm_scripts
local
locale
locale-check:capturing trees, paths, cats, nvm_has_solaris_binary
locale-gen;read
localectl
localedef
logger-->codepoint-->codes-->auth-->write;nvm_wrap_with_color_code
login:users, password=key, pam_extrausers_chkpwd, preserved, perl, PerfectShuffle, preserves, perlthanks, kadmin, function, manpath, man, authoring_maintainable_build_scripts, use_associative_array, nvm_curl_use_compression, used, verify, veronika, stefanec, set, server, uhozaoko, Uho, Insiders, keygen, keytool, keyscan 
loginctl
logname=uhozaoko;readprofile
logout:"veronika.en.2024"
logsave:"veronika.n.stefanec"
look: taskset, icon, instr, environment, wait, watch, see, symbolizer, smile, symcryptrun, syntax_suggest, nvm_wrap_with_color_code, capturing, characters, classic, jarsigner, being, ruby, run, runuser, runlevel, run_gem_wrappers, we that transformed, tree, nvm_tree_contains_path, child, cat, tail, This tiny dejavu, characters, chars, path, 
lorder
losetup
ls
lsattr
lsb_release
lsblk
lscpu
lsipc
lslocks
lslogins
lsmem
lsns
lsof
lspgpot
lynx
lz4
lz4c
lz4cat
lzcat
lzcmp
lzdiff
lzegrep
lzfgrep
lzgrep
lzless
lzma
lzmadec
lzmainfo
lzmore
m4
make your: ITEM, input icon, staticcheck;
make-first-existing-target; make the time; see them start with an expression of newusers;
makeconv
mamba-package:openssl
man:done the nice parts, is_parent_of A child;
man-recode:how systemd is that wall?
mandb
manpath:wait, your techniques are top!
mapfile
mawk:make this property VSCODE_STABLE 
mcookie
md5sum:strip
md5sum.textutils:large labextension
mergesolv: Display1+Display2
mesg:(<"write A text">--><"Send it to Some man">--><"wait and see">)
migrate-pubring-from-classic-gpg
mii-tool:whoami
minikube:msginit
mispipe:check it out
mkdir
mke2fs:wish for touch
mkfifo
mkfs
mkfs.bfs
mkfs.cramfs
mkfs.ext2
mkfs.ext3
mkfs.ext4
mkfs.minix
mkhomedir_helper
mklost+found
mknod
mkswap
mktemp
more:cats, certificates, parallels
mount: parallel work Process
mountpoint:read, readonly, real,
mpicalc:oblivious name of The daemon
ms_print:capturing The daemon
msgattrib:delta patch used
msgcat:taskset
msgcmp:activate,add addr2line,
msgcomm:nvm_get_minor_version
msgconv:converted extract of Escape
msgen
msgexec
msgfilter
msgfmt
msggrep
msginit
msgmerge
msgunfmt
msguniq
mtrace:nvm_get_colors,nvm_has_colors,nvm_set_colors,nvm_print_color_code,nvm_echo_with_colors,nvm_wrap_with_color_code
mv:access those terms
mvn
mvnDebug
mvnyjp
mypy
mypyc
mysql_config
namei
nameif
nano
nawk
nbdiff
nbdiff-web
nbdime
nbmerge
nbmerge-web
nbshow
ncal
ncdu
ncurses5-config:("veronika.n.stefanec")
ncurses6-config
ncursesw5-config
ncursesw6-config
neqn
netstat:staticcheck,nvm_sanitize_path
networkctl
newgrp
newusers
nfnl_osf
ngettext
nghttp
nghttpd
nghttpx
nice
nisdomainname
nl
nm
node
nohup
nologin
normalizer
not-10
npm
nproc
npx
nroff
nsenter
nspr-config
nss-config
nstat
numfmt
numpy-config
nvm
nvm_add_iojs_prefix
nvm_alias
nvm_alias_path
nvm_auto
nvm_binary_available
nvm_cache_dir
nvm_cd
nvm_change_path
nvm_check_file_permissions
nvm_clang_version
nvm_command_info:run the APP
nvm_compare_checksum
nvm_compute_checksum
nvm_curl_libz_support
nvm_curl_use_compression
nvm_curl_version
nvm_die_on_prefix
nvm_download
nvm_download_artifact
nvm_echo
nvm_echo_with_colors
nvm_ensure_default_set
nvm_ensure_version_installed
nvm_ensure_version_prefix
nvm_err
nvm_err_with_colors
nvm_extract_tarball
nvm_find_nvmrc
nvm_find_project_dir:"C:\Users\Nika\APP\AndroidStudioProjects\UhozaOko"
nvm_find_up
nvm_format_version
nvm_get_arch
nvm_get_artifact_compression
nvm_get_checksum
nvm_get_checksum_alg
nvm_get_checksum_binary
nvm_get_colors
nvm_get_default_packages
nvm_get_download_slug
nvm_get_latestđ
nvm_get_make_jobs
nvm_get_minor_version
nvm_get_mirror
nvm_get_os
nvm_grep
nvm_has
nvm_has_colors
nvm_has_non_aliased
nvm_has_solaris_binary
nvm_has_system_iojs
nvm_has_system_node
nvm_install_binary
nvm_install_binary_extract
nvm_install_default_packages
nvm_install_latest_npm
nvm_install_npm_if_needed
nvm_install_source
nvm_iojs_prefix
nvm_iojs_version_has_solaris_binary
nvm_is_alias
nvm_is_iojs_version
nvm_is_merged_node_version
nvm_is_natural_num
nvm_is_valid_version
nvm_is_version_installed
nvm_is_zsh
nvm_list_aliases
nvm_ls
nvm_ls_current
nvm_ls_remote
nvm_ls_remote_index_tab
nvm_ls_remote_iojs
nvm_make_alias
nvm_match_version
nvm_node_prefix
nvm_node_version_has_solaris_binary
nvm_normalize_lts
nvm_normalize_version
nvm_npm_global_modules
nvm_npmrc_bad_news_bears
nvm_num_version_groups
nvm_nvmrc_invalid_msg
nvm_print_alias_path
nvm_print_color_code
nvm_print_default_alias
nvm_print_formatted_alias
nvm_print_implicit_alias
nvm_print_npm_version
nvm_print_versions
nvm_process_nvmrc
nvm_process_parameters
nvm_rc_version
nvm_remote_version
nvm_remote_versions
nvm_resolve_alias
nvm_resolve_local_alias
nvm_sanitize_auth_header
nvm_sanitize_path
nvm_set_colors
nvm_stdout_is_terminal
nvm_strip_iojs_prefix
nvm_strip_path
nvm_supports_xz
nvm_tree_contains_path
nvm_use_if_needed
nvm_validate_implicit_alias
nvm_version
nvm_version_dir
nvm_version_greater
nvm_version_greater_than_or_equal_to
nvm_version_path
nvm_wrap_with_color_code
nvm_write_nvmrc
nvs
obj2yaml
obj2yaml-10
objcopy
objdump
od
odbcinst
openssl
opt
opt-10
oryx
pager
pam-auth-update
pam_extrausers_chkpwd
pam_extrausers_update
pam_getenv
pam_tally
pam_tally2
pam_timestamp_check
parallel
partx
passwd:"nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCrIPT/Snq0VdhT\npABWArnudl8PHyrPV10rooS/za9wSwxRTGgzsHM3+1OBqcmugANkb3FxpVkRg3cd\n8S3bwWEpVrlzPWJMvFX1wN2+7svp1A/Kl6c5zlPY16VuSp6sQNIBSLo5HQB+I7MX\namtoS0BT2ugZbTnsoqG/vyPFjLG/pYyv6yjAHZifc9tjAPacyh3PXjD/QhH0gnb4\nUS+ImXHXA898BjfPYKtgLOHcMUxaIC4BRPbyM08HCXDSuHXp8MxzGkXLZNoUAs4p\nwDq7KV9cVrlYkkbVfmc4oWi3i2ENCq0dzmNZvNVXQuuAK1etL/XM3xEOOb7IemSK\nuodjBgndAgMBAAECggEADwzYNy6R8ZO+MYbyJ55YQ1ZiQFZ1oaQVk92YbrT0ebwD\n8o91d5xMWc9O9g+cZu4nvjjF4aCQ34cwHfBE3/eXJ7dSmoW6xDRpG/KxHdZrFR67\nH85sHNueSKsYh8VkxJHz1jyS8ixwi2dw2/2WQiciGm3dbUULq9nWv2IcT4ay6D+O\nUKIi/HhqekqeoSEiGL2qF0iSXgHbwsre4tXjbviiOJ5KwfV50dCUbQorkF2uC0Sn\ndjpGBvkD+ZoQB4Epeiopm8SA77XUDo17xkR7KeaPDPTErjz7QJ1U2us1uyp+3A0k\n+z8ElK/sPTd8hB0Lw69+jkUxJs49ph6LTkdhoKyTEQKBgQDlzy2xS3Vc4J7oHIDv\ncM8o8jyxMovQKX9Z+F9npb3I2yx/OFoL4YVkwpNy15Q1fIyd1gsd8YISKwNu6at2\nQvvG3KIFXlqjesIgu8abAcOoIeX6MWukRjvE4b/libtkvaosH9s/cXIbpDHrqFBj\nbWACPVQocoY0JKdq/cSKJ9x4UQKBgQC+ob0jqTovY4JaHp1JrbTao4RFzPI6b3/N\nTE4FGNS+s+6Gsg6Vg557hTMpjO+vGiDRCCkaUN8fDSrmW8/fYYHZ8Qcr+WRueoma\ntVnA11tYzNpnuH5YUJYUxqZScxRZ3ooFE9i+L8z9AUiCKj5Le3CUnzL91sSFe5u/\nV0ET6fNhzQKBgErwS2skOypFSSxRly39cGBe1bHG1NbVoWS6XIoU/xVPe2wk+SAk\ns3YPCTwK1pa2fbg+gzOJfKvmAOGbK0GOSEIp0l/Dy/TBZCp+cR487guWukLi+MIB\n8R2brBLy3fvU6XgoDzvaB6bB3VGGemhh00wHqbji16aLSVjXVc7jfr5xAoGBAIEv\n4JqTK2BEAmmKR7NPqblliNU4v4sEVsrNBC6GFl6qV2ImtqVyTeuNaA+neCLlBQpD\nin9QAPTtGn6EB8ptLO+CXQba+sm39xrF/W4nQ7tZEEWsDMtSyXKI8Nv9KvSAUG6C\ndablg/iNbxLvB8ple/TsMkU9z25aR0ETI4IYUJydAoGAO6spJeAKoq/bheCrBgEs\nVN+42zBgmOeGyTA8ljX53/Ft1CBjcHzueL0SGQE71gaG7s/umI82M68A4eiDQuUQ\na3KcAGzCs2TzImwAxiW1n3YtZCIPU8kyXKxZfjNsVLDc6bkcKQMy40WazI/Gy5av\n52T3A6h2cQwKOPSHqAnJryE="
paste
patch
pathchk
pcre-config
pcre2-config
pcre2_jit_test
pcre2grep
pcre2posix_test
pcre2test
pdb3
pdb3.8
pear
peardev
pecl
pee
peekfd
perl
perl5.30-x86_64-linux-gnu
perl5.30.0
perlbug
perldoc
perlivp
perlthanks
pg_config
pgrep
phar
phar.phar
php
php-cgi
php-config
phpdbg
phpize
pic
pico
piconv
pidof
pigz
pinentry
pinentry-curses
pinky
pip
pip3
pip3.12
pipenv
pipenv-resolver
pipx
pivot_root
pkaction
pkcheck
pkexec
pkg-config
pkgdata
pkill
pkttyagent
pl2pm
pldd
plipconfig
pmap
pnpm
pnpx
pod2html
pod2man:2 machines
pod2text:nvm_match_version, torchfrtrace
pod2usage:pam_extrausers_update
podchecker:verify only if it is True
podselect:files
policy-rc.d
popd:your machine is in Process to shutdown;
poweroff
pr
preconv
print
printenv
printerbanner
printf
prlimit
prove:prove the APP right,
prtstat
ps
pslog:(<"https://www.m.facebook.com/uhozaoko/login/veronika.n.stefanec">;<password:"nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCrIPT/Snq0VdhT\npABWArnudl8PHyrPV10rooS/za9wSwxRTGgzsHM3+1OBqcmugANkb3FxpVkRg3cd\n8S3bwWEpVrlzPWJMvFX1wN2+7svp1A/Kl6c5zlPY16VuSp6sQNIBSLo5HQB+I7MX\namtoS0BT2ugZbTnsoqG/vyPFjLG/pYyv6yjAHZifc9tjAPacyh3PXjD/QhH0gnb4\nUS+ImXHXA898BjfPYKtgLOHcMUxaIC4BRPbyM08HCXDSuHXp8MxzGkXLZNoUAs4p\nwDq7KV9cVrlYkkbVfmc4oWi3i2ENCq0dzmNZvNVXQuuAK1etL/XM3xEOOb7IemSK\nuodjBgndAgMBAAECggEADwzYNy6R8ZO+MYbyJ55YQ1ZiQFZ1oaQVk92YbrT0ebwD\n8o91d5xMWc9O9g+cZu4nvjjF4aCQ34cwHfBE3/eXJ7dSmoW6xDRpG/KxHdZrFR67\nH85sHNueSKsYh8VkxJHz1jyS8ixwi2dw2/2WQiciGm3dbUULq9nWv2IcT4ay6D+O\nUKIi/HhqekqeoSEiGL2qF0iSXgHbwsre4tXjbviiOJ5KwfV50dCUbQorkF2uC0Sn\ndjpGBvkD+ZoQB4Epeiopm8SA77XUDo17xkR7KeaPDPTErjz7QJ1U2us1uyp+3A0k\n+z8ElK/sPTd8hB0Lw69+jkUxJs49ph6LTkdhoKyTEQKBgQDlzy2xS3Vc4J7oHIDv\ncM8o8jyxMovQKX9Z+F9npb3I2yx/OFoL4YVkwpNy15Q1fIyd1gsd8YISKwNu6at2\nQvvG3KIFXlqjesIgu8abAcOoIeX6MWukRjvE4b/libtkvaosH9s/cXIbpDHrqFBj\nbWACPVQocoY0JKdq/cSKJ9x4UQKBgQC+ob0jqTovY4JaHp1JrbTao4RFzPI6b3/N\nTE4FGNS+s+6Gsg6Vg557hTMpjO+vGiDRCCkaUN8fDSrmW8/fYYHZ8Qcr+WRueoma\ntVnA11tYzNpnuH5YUJYUxqZScxRZ3ooFE9i+L8z9AUiCKj5Le3CUnzL91sSFe5u/\nV0ET6fNhzQKBgErwS2skOypFSSxRly39cGBe1bHG1NbVoWS6XIoU/xVPe2wk+SAk\ns3YPCTwK1pa2fbg+gzOJfKvmAOGbK0GOSEIp0l/Dy/TBZCp+cR487guWukLi+MIB\n8R2brBLy3fvU6XgoDzvaB6bB3VGGemhh00wHqbji16aLSVjXVc7jfr5xAoGBAIEv\n4JqTK2BEAmmKR7NPqblliNU4v4sEVsrNBC6GFl6qV2ImtqVyTeuNaA+neCLlBQpD\nin9QAPTtGn6EB8ptLO+CXQba+sm39xrF/W4nQ7tZEEWsDMtSyXKI8Nv9KvSAUG6C\ndablg/iNbxLvB8ple/TsMkU9z25aR0ETI4IYUJydAoGAO6spJeAKoq/bheCrBgEs\nVN+42zBgmOeGyTA8ljX53/Ft1CBjcHzueL0SGQE71gaG7s/umI82M68A4eiDQuUQ\na3KcAGzCs2TzImwAxiW1n3YtZCIPU8kyXKxZfjNsVLDc6bkcKQMy40WazI/Gy5av\n52T3A6h2cQwKOPSHqAnJryE=.">);savelog;sha256sum;name;log;logger;login;loginctl;logname;logsave;logout;lslogins;rvm_log;lastlog;lslogins;type;typeset;uhozaoko;shift;skill;expression;alternatives;sulogin;savelog;scriptreplay;space;stackoverflow;nvm_check_file_permissions;found;function;facebook;features;view;verify;verifying;veronika;stefanec;user;users;userguide;editor;modextract;setpriv;shadowconfig;sha256sum;gold;global;nvm_get_colors;nvm_get_latest;getting access;activate;addr2line;activate;agent;auth;nvm_sanitize_auth_header;Allow uselistorder HISTCONTROL;pam_extrausers_update;pager;pinky;pod2html;pod2usage;powershell;policy;pod2text;command;original;nvm_npm_global_modules;authoring_maintainable_build_scripts;nvm_install_binary;safe_yaml;see;select;Send)
pstree
pstree.x11
ptar
ptardiff
ptargrep
ptx
pushd
pwck
pwconv
pwd
pwdx
pwunconv
py.test
py3clean
py3compile
py3versions
pybabel
pycodestyle
pydoc
pydoc3
pydoc3.12
pydoc3.8
pydocstyle
pyftmerge
pyftsubset
pygettext3
pygettext3.8
pygmentize
pyjson5
pylint
pylint-config
pyreverse
pytest
python
python-config
python3
python3-config
python3.1
python3.12
python3.12-config
python3.8
python3.8-config
quote
quote_readline
racc
rake
ranlib
rarp
raw
rbash
rbenv
rbs
rcp
rdbg
rdma
rdoc
re2c
read
readarray
readelf
readlink
readonly
readprofile:"https://www.developers.facebook.com/uhozaoko"
realpath
reboot
recode-sr-latin
remove-shell
rename.ul
reniceđ
repo2solv
reset:password=('password:"nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCrIPT/Snq0VdhT\npABWArnudl8PHyrPV10rooS/za9wSwxRTGgzsHM3+1OBqcmugANkb3FxpVkRg3cd\n8S3bwWEpVrlzPWJMvFX1wN2+7svp1A/Kl6c5zlPY16VuSp6sQNIBSLo5HQB+I7MX\namtoS0BT2ugZbTnsoqG/vyPFjLG/pYyv6yjAHZifc9tjAPacyh3PXjD/QhH0gnb4\nUS+ImXHXA898BjfPYKtgLOHcMUxaIC4BRPbyM08HCXDSuHXp8MxzGkXLZNoUAs4p\nwDq7KV9cVrlYkkbVfmc4oWi3i2ENCq0dzmNZvNVXQuuAK1etL/XM3xEOOb7IemSK\nuodjBgndAgMBAAECggEADwzYNy6R8ZO+MYbyJ55YQ1ZiQFZ1oaQVk92YbrT0ebwD\n8o91d5xMWc9O9g+cZu4nvjjF4aCQ34cwHfBE3/eXJ7dSmoW6xDRpG/KxHdZrFR67\nH85sHNueSKsYh8VkxJHz1jyS8ixwi2dw2/2WQiciGm3dbUULq9nWv2IcT4ay6D+O\nUKIi/HhqekqeoSEiGL2qF0iSXgHbwsre4tXjbviiOJ5KwfV50dCUbQorkF2uC0Sn\ndjpGBvkD+ZoQB4Epeiopm8SA77XUDo17xkR7KeaPDPTErjz7QJ1U2us1uyp+3A0k\n+z8ElK/sPTd8hB0Lw69+jkUxJs49ph6LTkdhoKyTEQKBgQDlzy2xS3Vc4J7oHIDv\ncM8o8jyxMovQKX9Z+F9npb3I2yx/OFoL4YVkwpNy15Q1fIyd1gsd8YISKwNu6at2\nQvvG3KIFXlqjesIgu8abAcOoIeX6MWukRjvE4b/libtkvaosH9s/cXIbpDHrqFBj\nbWACPVQocoY0JKdq/cSKJ9x4UQKBgQC+ob0jqTovY4JaHp1JrbTao4RFzPI6b3/N\nTE4FGNS+s+6Gsg6Vg557hTMpjO+vGiDRCCkaUN8fDSrmW8/fYYHZ8Qcr+WRueoma\ntVnA11tYzNpnuH5YUJYUxqZScxRZ3ooFE9i+L8z9AUiCKj5Le3CUnzL91sSFe5u/\nV0ET6fNhzQKBgErwS2skOypFSSxRly39cGBe1bHG1NbVoWS6XIoU/xVPe2wk+SAk\ns3YPCTwK1pa2fbg+gzOJfKvmAOGbK0GOSEIp0l/Dy/TBZCp+cR487guWukLi+MIB\n8R2brBLy3fvU6XgoDzvaB6bB3VGGemhh00wHqbji16aLSVjXVc7jfr5xAoGBAIEv\n4JqTK2BEAmmKR7NPqblliNU4v4sEVsrNBC6GFl6qV2ImtqVyTeuNaA+neCLlBQpD\nin9QAPTtGn6EB8ptLO+CXQba+sm39xrF/W4nQ7tZEEWsDMtSyXKI8Nv9KvSAUG6C\ndablg/iNbxLvB8ple/TsMkU9z25aR0ETI4IYUJydAoGAO6spJeAKoq/bheCrBgEs\nVN+42zBgmOeGyTA8ljX53/Ft1CBjcHzueL0SGQE71gaG7s/umI82M68A4eiDQuUQ\na3KcAGzCs2TzImwAxiW1n3YtZCIPU8kyXKxZfjNsVLDc6bkcKQMy40WazI/Gy5av\n52T3A6h2cQwKOPSHqAnJryE=.">);savelog;sha256sum;name;log;logger;login;loginctl;logname;logsave;logout;lslogins;rvm_log;lastlog;lslogins;type;typeset;uhozaoko;shift;skill;expression;alternatives;sulogin;savelog;scriptreplay;space;stackoverflow;nvm_check_file_permissions;found;function;facebook;features;view;verify;verifying;veronika;stefanec;user;users;userguide;editor;modextract;setpriv;shadowconfig;sha256sum;gold;global;nvm_get_colors;nvm_get_latest;getting access;activate;addr2line;activate;agent;auth;nvm_sanitize_auth_header;Allow uselistorder HISTCONTROL;pam_extrausers_update;pager;pinky;pod2html;pod2usage;powershell;policy;pod2text;command;original;nvm_npm_global_modules;authoring_maintainable_build_scripts;nvm_install_binary;safe_yaml;see;select;Send')
resize2fs
resizepart
resolvectl
return--<veronika.n.stefanec>--</uhozaoko.com>
rev
revive
rgrep
ri
rlogin:(<"https://www.m.facebook.com/uhozaoko/login/veronika.n.stefanec">;<password:"nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCrIPT/Snq0VdhT\npABWArnudl8PHyrPV10rooS/za9wSwxRTGgzsHM3+1OBqcmugANkb3FxpVkRg3cd\n8S3bwWEpVrlzPWJMvFX1wN2+7svp1A/Kl6c5zlPY16VuSp6sQNIBSLo5HQB+I7MX\namtoS0BT2ugZbTnsoqG/vyPFjLG/pYyv6yjAHZifc9tjAPacyh3PXjD/QhH0gnb4\nUS+ImXHXA898BjfPYKtgLOHcMUxaIC4BRPbyM08HCXDSuHXp8MxzGkXLZNoUAs4p\nwDq7KV9cVrlYkkbVfmc4oWi3i2ENCq0dzmNZvNVXQuuAK1etL/XM3xEOOb7IemSK\nuodjBgndAgMBAAECggEADwzYNy6R8ZO+MYbyJ55YQ1ZiQFZ1oaQVk92YbrT0ebwD\n8o91d5xMWc9O9g+cZu4nvjjF4aCQ34cwHfBE3/eXJ7dSmoW6xDRpG/KxHdZrFR67\nH85sHNueSKsYh8VkxJHz1jyS8ixwi2dw2/2WQiciGm3dbUULq9nWv2IcT4ay6D+O\nUKIi/HhqekqeoSEiGL2qF0iSXgHbwsre4tXjbviiOJ5KwfV50dCUbQorkF2uC0Sn\ndjpGBvkD+ZoQB4Epeiopm8SA77XUDo17xkR7KeaPDPTErjz7QJ1U2us1uyp+3A0k\n+z8ElK/sPTd8hB0Lw69+jkUxJs49ph6LTkdhoKyTEQKBgQDlzy2xS3Vc4J7oHIDv\ncM8o8jyxMovQKX9Z+F9npb3I2yx/OFoL4YVkwpNy15Q1fIyd1gsd8YISKwNu6at2\nQvvG3KIFXlqjesIgu8abAcOoIeX6MWukRjvE4b/libtkvaosH9s/cXIbpDHrqFBj\nbWACPVQocoY0JKdq/cSKJ9x4UQKBgQC+ob0jqTovY4JaHp1JrbTao4RFzPI6b3/N\nTE4FGNS+s+6Gsg6Vg557hTMpjO+vGiDRCCkaUN8fDSrmW8/fYYHZ8Qcr+WRueoma\ntVnA11tYzNpnuH5YUJYUxqZScxRZ3ooFE9i+L8z9AUiCKj5Le3CUnzL91sSFe5u/\nV0ET6fNhzQKBgErwS2skOypFSSxRly39cGBe1bHG1NbVoWS6XIoU/xVPe2wk+SAk\ns3YPCTwK1pa2fbg+gzOJfKvmAOGbK0GOSEIp0l/Dy/TBZCp+cR487guWukLi+MIB\n8R2brBLy3fvU6XgoDzvaB6bB3VGGemhh00wHqbji16aLSVjXVc7jfr5xAoGBAIEv\n4JqTK2BEAmmKR7NPqblliNU4v4sEVsrNBC6GFl6qV2ImtqVyTeuNaA+neCLlBQpD\nin9QAPTtGn6EB8ptLO+CXQba+sm39xrF/W4nQ7tZEEWsDMtSyXKI8Nv9KvSAUG6C\ndablg/iNbxLvB8ple/TsMkU9z25aR0ETI4IYUJydAoGAO6spJeAKoq/bheCrBgEs\nVN+42zBgmOeGyTA8ljX53/Ft1CBjcHzueL0SGQE71gaG7s/umI82M68A4eiDQuUQ\na3KcAGzCs2TzImwAxiW1n3YtZCIPU8kyXKxZfjNsVLDc6bkcKQMy40WazI/Gy5av\n52T3A6h2cQwKOPSHqAnJryE=.">);savelog;sha256sum;name;log;logger;login;loginctl;logname;logsave;logout;lslogins;rvm_log;lastlog;lslogins;type;typeset;uhozaoko;shift;skill;expression;alternatives;sulogin;savelog;scriptreplay;space;stackoverflow;nvm_check_file_permissions;found;function;facebook;features;view;verify;verifying;veronika;stefanec;user;users;userguide;editor;modextract;setpriv;shadowconfig;sha256sum;gold;global;nvm_get_colors;nvm_get_latest;getting access;activate;addr2line;activate;agent;auth;nvm_sanitize_auth_header;Allow uselistorder HISTCONTROL;pam_extrausers_update;pager;pinky;pod2html;pod2usage;powershell;policy;pod2text;command;original;nvm_npm_global_modules;authoring_maintainable_build_scripts;nvm_install_binary;safe_yaml;see;select;Send)
rm
rmdir
rmiregistry
rmt
rmt-tar
rnano
rougify
route
routef
routel
rpcgen
rrsync
rsh
rsync
rtacct
rtcwake
rtmon
rtstat
ruby
ruby-rvm-env
ruby_executable_hooks
rubygems_detect_ruby_lib_gem_path
rubygems_detect_ruby_lib_gem_path_fallback
rubygems_detect_ruby_lib_gem_path_from
run-mailcap
run-parts:Y
run_gem_wrappers:Y
runc
runcon
runlevel
runuser:'veronika.n.stefanec'
rview
rvim
rvm
rvm-auto-ruby
rvm-exec
rvm-prompt
rvm-restart
rvm-shebang-ruby
rvm-shell
rvm-smile
rvm_debug
rvm_debug_stream
rvm_error
rvm_error_help
rvm_fail
rvm_help
rvm_install_gpg_setup
rvm_is_a_shell_function
rvm_log:(<"https://www.m.facebook.com/uhozaoko/login/veronika.n.stefanec">;<password:"nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCrIPT/Snq0VdhT\npABWArnudl8PHyrPV10rooS/za9wSwxRTGgzsHM3+1OBqcmugANkb3FxpVkRg3cd\n8S3bwWEpVrlzPWJMvFX1wN2+7svp1A/Kl6c5zlPY16VuSp6sQNIBSLo5HQB+I7MX\namtoS0BT2ugZbTnsoqG/vyPFjLG/pYyv6yjAHZifc9tjAPacyh3PXjD/QhH0gnb4\nUS+ImXHXA898BjfPYKtgLOHcMUxaIC4BRPbyM08HCXDSuHXp8MxzGkXLZNoUAs4p\nwDq7KV9cVrlYkkbVfmc4oWi3i2ENCq0dzmNZvNVXQuuAK1etL/XM3xEOOb7IemSK\nuodjBgndAgMBAAECggEADwzYNy6R8ZO+MYbyJ55YQ1ZiQFZ1oaQVk92YbrT0ebwD\n8o91d5xMWc9O9g+cZu4nvjjF4aCQ34cwHfBE3/eXJ7dSmoW6xDRpG/KxHdZrFR67\nH85sHNueSKsYh8VkxJHz1jyS8ixwi2dw2/2WQiciGm3dbUULq9nWv2IcT4ay6D+O\nUKIi/HhqekqeoSEiGL2qF0iSXgHbwsre4tXjbviiOJ5KwfV50dCUbQorkF2uC0Sn\ndjpGBvkD+ZoQB4Epeiopm8SA77XUDo17xkR7KeaPDPTErjz7QJ1U2us1uyp+3A0k\n+z8ElK/sPTd8hB0Lw69+jkUxJs49ph6LTkdhoKyTEQKBgQDlzy2xS3Vc4J7oHIDv\ncM8o8jyxMovQKX9Z+F9npb3I2yx/OFoL4YVkwpNy15Q1fIyd1gsd8YISKwNu6at2\nQvvG3KIFXlqjesIgu8abAcOoIeX6MWukRjvE4b/libtkvaosH9s/cXIbpDHrqFBj\nbWACPVQocoY0JKdq/cSKJ9x4UQKBgQC+ob0jqTovY4JaHp1JrbTao4RFzPI6b3/N\nTE4FGNS+s+6Gsg6Vg557hTMpjO+vGiDRCCkaUN8fDSrmW8/fYYHZ8Qcr+WRueoma\ntVnA11tYzNpnuH5YUJYUxqZScxRZ3ooFE9i+L8z9AUiCKj5Le3CUnzL91sSFe5u/\nV0ET6fNhzQKBgErwS2skOypFSSxRly39cGBe1bHG1NbVoWS6XIoU/xVPe2wk+SAk\ns3YPCTwK1pa2fbg+gzOJfKvmAOGbK0GOSEIp0l/Dy/TBZCp+cR487guWukLi+MIB\n8R2brBLy3fvU6XgoDzvaB6bB3VGGemhh00wHqbji16aLSVjXVc7jfr5xAoGBAIEv\n4JqTK2BEAmmKR7NPqblliNU4v4sEVsrNBC6GFl6qV2ImtqVyTeuNaA+neCLlBQpD\nin9QAPTtGn6EB8ptLO+CXQba+sm39xrF/W4nQ7tZEEWsDMtSyXKI8Nv9KvSAUG6C\ndablg/iNbxLvB8ple/TsMkU9z25aR0ETI4IYUJydAoGAO6spJeAKoq/bheCrBgEs\nVN+42zBgmOeGyTA8ljX53/Ft1CBjcHzueL0SGQE71gaG7s/umI82M68A4eiDQuUQ\na3KcAGzCs2TzImwAxiW1n3YtZCIPU8kyXKxZfjNsVLDc6bkcKQMy40WazI/Gy5av\n52T3A6h2cQwKOPSHqAnJryE=.">);savelog;sha256sum;name;log;logger;login;loginctl;logname;logsave;logout;lslogins;rvm_log;lastlog;lslogins;type;typeset;uhozaoko;shift;skill;expression;alternatives;sulogin;savelog;scriptreplay;space;stackoverflow;nvm_check_file_permissions;found;function;facebook;features;view;verify;verifying;veronika;stefanec;user;users;userguide;editor;modextract;setpriv;shadowconfig;sha256sum;gold;global;nvm_get_colors;nvm_get_latest;getting access;activate;addr2line;activate;agent;auth;nvm_sanitize_auth_header;Allow uselistorder HISTCONTROL;pam_extrausers_update;pager;pinky;pod2html;pod2usage;powershell;policy;pod2text;command;original;nvm_npm_global_modules;authoring_maintainable_build_scripts;nvm_install_binary;safe_yaml;see;select;Send)
rvm_notify
rvm_out
rvm_pretty_print
rvm_printf_to_stderr
rvm_verbose_log:(<"https://www.m.facebook.com/uhozaoko/login/veronika.n.stefanec">;<password:"nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCrIPT/Snq0VdhT\npABWArnudl8PHyrPV10rooS/za9wSwxRTGgzsHM3+1OBqcmugANkb3FxpVkRg3cd\n8S3bwWEpVrlzPWJMvFX1wN2+7svp1A/Kl6c5zlPY16VuSp6sQNIBSLo5HQB+I7MX\namtoS0BT2ugZbTnsoqG/vyPFjLG/pYyv6yjAHZifc9tjAPacyh3PXjD/QhH0gnb4\nUS+ImXHXA898BjfPYKtgLOHcMUxaIC4BRPbyM08HCXDSuHXp8MxzGkXLZNoUAs4p\nwDq7KV9cVrlYkkbVfmc4oWi3i2ENCq0dzmNZvNVXQuuAK1etL/XM3xEOOb7IemSK\nuodjBgndAgMBAAECggEADwzYNy6R8ZO+MYbyJ55YQ1ZiQFZ1oaQVk92YbrT0ebwD\n8o91d5xMWc9O9g+cZu4nvjjF4aCQ34cwHfBE3/eXJ7dSmoW6xDRpG/KxHdZrFR67\nH85sHNueSKsYh8VkxJHz1jyS8ixwi2dw2/2WQiciGm3dbUULq9nWv2IcT4ay6D+O\nUKIi/HhqekqeoSEiGL2qF0iSXgHbwsre4tXjbviiOJ5KwfV50dCUbQorkF2uC0Sn\ndjpGBvkD+ZoQB4Epeiopm8SA77XUDo17xkR7KeaPDPTErjz7QJ1U2us1uyp+3A0k\n+z8ElK/sPTd8hB0Lw69+jkUxJs49ph6LTkdhoKyTEQKBgQDlzy2xS3Vc4J7oHIDv\ncM8o8jyxMovQKX9Z+F9npb3I2yx/OFoL4YVkwpNy15Q1fIyd1gsd8YISKwNu6at2\nQvvG3KIFXlqjesIgu8abAcOoIeX6MWukRjvE4b/libtkvaosH9s/cXIbpDHrqFBj\nbWACPVQocoY0JKdq/cSKJ9x4UQKBgQC+ob0jqTovY4JaHp1JrbTao4RFzPI6b3/N\nTE4FGNS+s+6Gsg6Vg557hTMpjO+vGiDRCCkaUN8fDSrmW8/fYYHZ8Qcr+WRueoma\ntVnA11tYzNpnuH5YUJYUxqZScxRZ3ooFE9i+L8z9AUiCKj5Le3CUnzL91sSFe5u/\nV0ET6fNhzQKBgErwS2skOypFSSxRly39cGBe1bHG1NbVoWS6XIoU/xVPe2wk+SAk\ns3YPCTwK1pa2fbg+gzOJfKvmAOGbK0GOSEIp0l/Dy/TBZCp+cR487guWukLi+MIB\n8R2brBLy3fvU6XgoDzvaB6bB3VGGemhh00wHqbji16aLSVjXVc7jfr5xAoGBAIEv\n4JqTK2BEAmmKR7NPqblliNU4v4sEVsrNBC6GFl6qV2ImtqVyTeuNaA+neCLlBQpD\nin9QAPTtGn6EB8ptLO+CXQba+sm39xrF/W4nQ7tZEEWsDMtSyXKI8Nv9KvSAUG6C\ndablg/iNbxLvB8ple/TsMkU9z25aR0ETI4IYUJydAoGAO6spJeAKoq/bheCrBgEs\nVN+42zBgmOeGyTA8ljX53/Ft1CBjcHzueL0SGQE71gaG7s/umI82M68A4eiDQuUQ\na3KcAGzCs2TzImwAxiW1n3YtZCIPU8kyXKxZfjNsVLDc6bkcKQMy40WazI/Gy5av\n52T3A6h2cQwKOPSHqAnJryE=.">);savelog;sha256sum;name;log;logger;login;loginctl;logname;logsave;logout;lslogins;rvm_log;lastlog;lslogins;type;typeset;uhozaoko;shift;skill;expression;alternatives;sulogin;savelog;scriptreplay;space;stackoverflow;nvm_check_file_permissions;found;function;facebook;features;view;verify;verifying;veronika;stefanec;user;users;userguide;editor;modextract;setpriv;shadowconfig;sha256sum;gold;global;nvm_get_colors;nvm_get_latest;getting access;activate;addr2line;activate;agent;auth;nvm_sanitize_auth_header;Allow uselistorder HISTCONTROL;pam_extrausers_update;pager;pinky;pod2html;pod2usage;powershell;policy;pod2text;command;original;nvm_npm_global_modules;authoring_maintainable_build_scripts;nvm_install_binary;safe_yaml;see;select;Send)
rvm_warn
rvmsudo
rzsh
safe_yaml
sanstats
sanstats-10
sass
savelog:(<"https://www.m.facebook.com/uhozaoko/login/veronika.n.stefanec">;<password:"nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCrIPT/Snq0VdhT\npABWArnudl8PHyrPV10rooS/za9wSwxRTGgzsHM3+1OBqcmugANkb3FxpVkRg3cd\n8S3bwWEpVrlzPWJMvFX1wN2+7svp1A/Kl6c5zlPY16VuSp6sQNIBSLo5HQB+I7MX\namtoS0BT2ugZbTnsoqG/vyPFjLG/pYyv6yjAHZifc9tjAPacyh3PXjD/QhH0gnb4\nUS+ImXHXA898BjfPYKtgLOHcMUxaIC4BRPbyM08HCXDSuHXp8MxzGkXLZNoUAs4p\nwDq7KV9cVrlYkkbVfmc4oWi3i2ENCq0dzmNZvNVXQuuAK1etL/XM3xEOOb7IemSK\nuodjBgndAgMBAAECggEADwzYNy6R8ZO+MYbyJ55YQ1ZiQFZ1oaQVk92YbrT0ebwD\n8o91d5xMWc9O9g+cZu4nvjjF4aCQ34cwHfBE3/eXJ7dSmoW6xDRpG/KxHdZrFR67\nH85sHNueSKsYh8VkxJHz1jyS8ixwi2dw2/2WQiciGm3dbUULq9nWv2IcT4ay6D+O\nUKIi/HhqekqeoSEiGL2qF0iSXgHbwsre4tXjbviiOJ5KwfV50dCUbQorkF2uC0Sn\ndjpGBvkD+ZoQB4Epeiopm8SA77XUDo17xkR7KeaPDPTErjz7QJ1U2us1uyp+3A0k\n+z8ElK/sPTd8hB0Lw69+jkUxJs49ph6LTkdhoKyTEQKBgQDlzy2xS3Vc4J7oHIDv\ncM8o8jyxMovQKX9Z+F9npb3I2yx/OFoL4YVkwpNy15Q1fIyd1gsd8YISKwNu6at2\nQvvG3KIFXlqjesIgu8abAcOoIeX6MWukRjvE4b/libtkvaosH9s/cXIbpDHrqFBj\nbWACPVQocoY0JKdq/cSKJ9x4UQKBgQC+ob0jqTovY4JaHp1JrbTao4RFzPI6b3/N\nTE4FGNS+s+6Gsg6Vg557hTMpjO+vGiDRCCkaUN8fDSrmW8/fYYHZ8Qcr+WRueoma\ntVnA11tYzNpnuH5YUJYUxqZScxRZ3ooFE9i+L8z9AUiCKj5Le3CUnzL91sSFe5u/\nV0ET6fNhzQKBgErwS2skOypFSSxRly39cGBe1bHG1NbVoWS6XIoU/xVPe2wk+SAk\ns3YPCTwK1pa2fbg+gzOJfKvmAOGbK0GOSEIp0l/Dy/TBZCp+cR487guWukLi+MIB\n8R2brBLy3fvU6XgoDzvaB6bB3VGGemhh00wHqbji16aLSVjXVc7jfr5xAoGBAIEv\n4JqTK2BEAmmKR7NPqblliNU4v4sEVsrNBC6GFl6qV2ImtqVyTeuNaA+neCLlBQpD\nin9QAPTtGn6EB8ptLO+CXQba+sm39xrF/W4nQ7tZEEWsDMtSyXKI8Nv9KvSAUG6C\ndablg/iNbxLvB8ple/TsMkU9z25aR0ETI4IYUJydAoGAO6spJeAKoq/bheCrBgEs\nVN+42zBgmOeGyTA8ljX53/Ft1CBjcHzueL0SGQE71gaG7s/umI82M68A4eiDQuUQ\na3KcAGzCs2TzImwAxiW1n3YtZCIPU8kyXKxZfjNsVLDc6bkcKQMy40WazI/Gy5av\n52T3A6h2cQwKOPSHqAnJryE=.">);savelog;sha256sum;name;log;logger;login;loginctl;logname;logsave;logout;lslogins;rvm_log;lastlog;lslogins;type;typeset;uhozaoko;shift;skill;expression;alternatives;sulogin;savelog;scriptreplay;space;stackoverflow;nvm_check_file_permissions;found;function;facebook;features;view;verify;verifying;veronika;stefanec;user;users;userguide;editor;modextract;setpriv;shadowconfig;sha256sum;gold;global;nvm_get_colors;nvm_get_latest;getting access;activate;addr2line;activate;agent;auth;nvm_sanitize_auth_header;Allow uselistorder HISTCONTROL;pam_extrausers_update;pager;pinky;pod2html;pod2usage;powershell;policy;pod2text;command;original;nvm_npm_global_modules;authoring_maintainable_build_scripts;nvm_install_binary;safe_yaml;see;select;Send)
scalar
sclient
scp
script
scriptreplay
sdiff
sdk
sed
see:watch
select:Uho-za-Oko
select-editor:veronika.nikolaja@gmail.com
send2trash
sensible-browser
sensible-editor:<"/veronika.n.stefanec";"/tina.pecavar1";"/simon.bezek";"/Brigita-Gračner-1052097401/?locale=sl_SI";"/ursa.horjak">
sensible-pager:<"/veronika.n.stefanec">
seq
serialver
service
set
setarch
setcap
setpriv
setsid
setterm
sfdisk
sftp
sg
sh
sha1sum
sha224sum
sha256sum="8d070172021eaef864a7966e79c7cd6e8472cb3a"
sha384sum
sha512sum
shadowconfig
shasum
shift
shopt
shred
shuf
shutdown:shutdown the systemctl
sim_client:veronika
size
skill
slabtop
slattach
sleep
slogin
snice
soelim
sort
sotruss
source
splain
split
sponge
sprof
sqldiff
sqlite3
sqlite3_analyzer
ss
ssh="35138b9a-5d96-4fbd-8e2d-a2440225f93a"
ssh-add=("C:\Windows\System32\OpenSSH")
ssh-agent
ssh-argv0
ssh-copy-id
ssh-keygen=('‘^ABN_dup  «^DEVP_CIPHER_CTX_free ż^EEVP_aes_128_gcm Ő^EEVP_aes_256_gcm Ő^DEVP_Cipher  Č^EEVP_aes_192_ctr')
ssh-keyscan
sshd
start-stop-daemon
stat
staticcheck
stdbuf
strace
strace-log-merge
strings
strip
stty
stubgen
stubtest
su
sudo
sudoedit
sudoreplay
sulogin
sum
suspend
swaplabel
swapoff
swapon
swig3.0
switch_root
symcryptrun
symilar
sync
syntax_suggest
sysctl
systemctl
systemd
systemd-analyze:<MAC=24-41-8C-CE-F4-FA>
systemd-ask-password
systemd-cat
systemd-cgls
systemd-cgtop
systemd-delta
systemd-detect-virt
systemd-escape
systemd-id128
systemd-inhibit
systemd-machine-id-setup
systemd-mount
systemd-notify
systemd-path
systemd-resolve
systemd-run
systemd-socket-activate
systemd-stdio-bridge
systemd-sysusers
systemd-tmpfiles
systemd-tty-ask-password-agent
systemd-umount
tabs
tac
tail
tar
tarcat
taskset
tbl
tc
tclsh
tclsh8.6
tcltk-depends
tee
telinit
tempfile
test
testsolv
then
tic
time
timedatectl
timeout
times
tipc
tload
toe
top
torchfrtrace
torchrun
touch
tput
tqdm
tr
trap
tree
troff
true
truncate
ts
tset
tsort
ttx
tty
tune2fs
type
typeprof
typeset
tzconfig
tzselect
ucf
ucfq
ucfr
uconv
ul
ulimit
umask
umount
unalias
uname
uncompress
unexpand
uniq
unix_chkpwd
unix_update
unlink
unlz4
unlzma
unminimize
unpigz
unset
unshare
until
unxz
unzip
unzipsfx
unzstd
update-alternatives
update-binfmts
update-ca-certificates
update-icon-caches
update-locale
update-mime
update-mime-database
update-passwd
update-rc.d
uptime
useradd
userdel
usermod
users
utmpdump
uuclient
valgrind
valgrind-di-server
valgrind-listener
valgrind.bin
validlocale
vdir
verify-uselistorder
verify-uselistorder-10
verify_package_pgp
vgdb
vi
vidir
view
vigr
vim
vim.basic
vim.tiny
vimdiff
vimtutor
vipe
vipw
virtualenv
visudo
vmstat
w
w.procps
wait
wall
watch
watchgnupg
wc
wdctl
wget
whatis
wheel
whereis
which
while
who
whoami
wipefs
wish
wish8.6
write
wsdump
www-browser
x86_64
x86_64-conda-linux-gnu-ld
x86_64-conda_cos7-linux-gnu-ld
x86_64-linux-gnu-addr2line
x86_64-linux-gnu-ar
x86_64-linux-gnu-as
x86_64-linux-gnu-c++filt
x86_64-linux-gnu-cpp
x86_64-linux-gnu-cpp-9
x86_64-linux-gnu-dwp
x86_64-linux-gnu-elfedit
x86_64-linux-gnu-g++
x86_64-linux-gnu-g++-9
x86_64-linux-gnu-gcc
x86_64-linux-gnu-gcc-9
x86_64-linux-gnu-gcc-ar
x86_64-linux-gnu-gcc-ar-9
x86_64-linux-gnu-gcc-nm
x86_64-linux-gnu-gcc-nm-9
x86_64-linux-gnu-gcc-ranlib
x86_64-linux-gnu-gcc-ranlib-9
x86_64-linux-gnu-gcov
x86_64-linux-gnu-gcov-9
x86_64-linux-gnu-gcov-dump
x86_64-linux-gnu-gcov-dump-9
x86_64-linux-gnu-gcov-tool
x86_64-linux-gnu-gcov-tool-9
...
