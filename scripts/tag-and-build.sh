#!/bin/bash
__SUMMARY__=$(cat <<"__END__"
Helper to tag and build a new version of this software, keeping release tags,
the spec version, and RPM changelog entries lined up.
__END__
)


SPEC=rpm/dataplacement.spec
PYPROJECT=pyproject.toml
BUILDRPM=scripts/buildrpm.sh
REQUIRED_BRANCH=devel


export PS4='+ ${FUNCNAME:-(top)}:${LINENO}: '

Prog=${0##*/}

ask_yn () {
    while read -rn1 -p "$* (y/n) "
    do
        echo >&2
        case $REPLY in
            [Yy]) return 0;;
            [Nn]) return 1;;
            *) echo >&2 "Enter y or n";;
        esac
    done
    return 2  # EOF
}

eecho () {
    echo >&2 "$@"
}

fail () {
    set +exu
    local ret=${1}
    shift
    echo -e "$Prog:" "$@" >&2
    exit "$ret"
}

usage () {
    echo >&2 "$__SUMMARY__"
    echo >&2
    echo >&2 "Usage: $Prog"
    exit "$1"
}

require_program () {
    command -v "$1" &>/dev/null ||
        fail 127 "Required program '$1' not found in PATH"
}

if [[ $* == -h || $* == --help ]]; then
    usage 0
fi

set -o nounset
IFS=$'\n\t'
unset GREP_OPTIONS POSIXLY_CORRECT

require_program git
require_program rpmspec





main () {
    REPO_ROOT=$(git rev-parse --show-toplevel)
    cd "$REPO_ROOT" || exit

    if [[ -n $(git status --porcelain) ]]; then
        fail 3 "The repository has uncommitted changes."
    fi

    VERSION=$(rpmspec -q --srpm --qf '%{VERSION}\n' "$SPEC")
    PYPROJECT_VERSION=$(awk -F '"' '
        /^\[project\][[:space:]]*$/ { in_project = 1; next }
        /^\[/ { in_project = 0 }
        in_project && /^[[:space:]]*version[[:space:]]*=/ {
            print $2
            exit
        }
    ' "$PYPROJECT")
    if [[ -z $PYPROJECT_VERSION ]]
    then
        fail 10 "Could not read project version from $PYPROJECT."
    fi
    if [[ $VERSION != "$PYPROJECT_VERSION" ]]
    then
        fail 10 "Aborting: spec version $VERSION does not match $PYPROJECT version $PYPROJECT_VERSION."
    fi

    CURRENT_TAG=$(git describe --tags --exact-match HEAD 2>/dev/null)

    if [[ -n $CURRENT_TAG ]]
    then
        # We're currently on a tag.
        TAG_VERSION=${CURRENT_TAG#v}
        if [[ $VERSION != "$TAG_VERSION" ]]
        then
            fail 4 "Aborting: spec version $VERSION does not match tag $CURRENT_TAG."
        fi

        if ask_yn "Build RPM for $CURRENT_TAG?"
        then
            "$BUILDRPM"
            return $?
        else
            eecho "Nothing more to do."
            return 0
        fi
    fi

    BRANCH=$(git branch --show-current)
    if [[ $BRANCH != "$REQUIRED_BRANCH" ]]
    then
        fail 5 "Not on branch '$REQUIRED_BRANCH'"
    fi

    if ! awk -v version="$VERSION" '
        /^%changelog$/ { in_changelog = 1; next }
        in_changelog && $0 ~ "-[[:space:]]*" version "[[:space:]]*$" {
            found = 1
            exit
        }
        END { exit !found }
    ' "$SPEC"
    then
        fail 6 "Entry for version $VERSION not found in %changelog. Please edit $SPEC and re-run."
    fi

    LATEST_TAG=$(git tag --sort=-version:refname | head -n 1)
    if [[ -n $LATEST_TAG ]]
    then
        LATEST_VERSION=${LATEST_TAG#v}
        # Check if the latest version is newer than the current one
        if [[ "$(printf '%s\n%s\n' "$LATEST_VERSION" "$VERSION" | sort -V | tail -n 1)" != "$VERSION" ||
              $LATEST_VERSION == "$VERSION" ]]
        then
            fail 7 "The spec version ($VERSION) is not newer than the latest tagged version ($LATEST_VERSION)."
        fi
    fi

    NEW_TAG="v$VERSION"
    if ! ask_yn "Create tag $NEW_TAG?"
    then
        echo "Exiting."
        return 0
    fi

    git tag "$NEW_TAG" || fail 8 "Could not create tag $NEW_TAG"

    if ask_yn "Build RPM for $NEW_TAG?"
    then
        "$BUILDRPM" || fail 9 "rpm build returned $?"
    fi
}

main "$@"; exit
