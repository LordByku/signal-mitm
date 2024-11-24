import platform
from abc import abstractmethod, ABCMeta

from plumbum import local, CommandNotFound

from setup.shell import execute


class UnsupportedPlatformError(Exception):
    pass


class PackageManager(metaclass=ABCMeta):
    """A generic package manager class."""

    def __init__(self):
        self.check_platform_support()

    @staticmethod
    def check_platform_support() -> None:
        if platform.system() != "Linux":
            raise UnsupportedPlatformError("This script only supports Linux platforms.")

    @abstractmethod
    def install(self, package_names: str | list[str]) -> None:
        raise NotImplementedError(
            f"Subclass {self.__class__.__name__} must provide an implementation for the `install` method."
        )

    @abstractmethod
    def update(self) -> None:
        raise NotImplementedError(
            f"Subclass {self.__class__.__name__} must provide an implementation for the `update` method."
        )

    @abstractmethod
    def install_kea(self) -> None:
        raise NotImplementedError(
            f"Subclass {self.__class__.__name__} must provide an implementation for the `install_kea` method."
        )

    @abstractmethod
    def search(self, package_name) -> str:
        raise NotImplementedError(
            f"Subclass {self.__class__.__name__} must provide an implementation for `search` method."
        )

    @abstractmethod
    def is_installed(self, package_name) -> bool:
        raise NotImplementedError(
            f"Subclass {self.__class__.__name__} must provide an implementation for `is_installed` method."
        )

    def __repr__(self):
        return f"{self.__class__.__name__}: a (Linux) package manager"


class AptPackageManager(PackageManager):
    """Package manager for Debian-based distributions (e.g., Ubuntu)."""

    def __init__(self):
        super().__init__()
        self.package_manager = local["apt-get"]
        self.dpkg_query = local["dpkg-query"]
        self.cache = local["apt-cache"]

    def install(self, package_names: str | list[str]) -> None:
        if isinstance(package_names, str):
            package_names = [package_names]

        print(
            f"Installing {', '.join(package_names)} using {self.__class__.__name__}..."
        )
        try:
            with local.env(DEBIAN_FRONTEND="noninteractive"):
                execute(
                    self.package_manager["install", "-y", "--show-progress", package_names],
                    as_sudo=True,
                    log=True,
                    retcodes=(0, 1),
                )
        except CommandNotFound:
            print(
                "apt-get command not found. Are you sure you're on a compatible platform?"
            )

    def update(self) -> None:
        print("Updating package list with apt...")
        execute(self.package_manager["update"], as_sudo=True, log=True)

    def __repr__(self):
        return "APT Package manager"

    def is_installed(self, package_name) -> bool:
        result = execute(self.dpkg_query["-l", package_name], log=True, retcodes=(0, 1))
        return result.retcode == 0

    def search(self, package_name) -> str:
        result = execute(self.cache["search", package_name], log=True, retcodes=(0, 1))
        return result.stdout  # TODO: do something useful with it

    def install_kea(self) -> None:
        self.install(["kea", "kea-doc"])


class DnfPackageManager(PackageManager):
    """Package manager for Red Hat-based distributions (e.g., Fedora)."""

    def __init__(self):
        super().__init__()
        self.package_manager = local["dnf"]

    def install(self, package_names: str | list[str]) -> None:
        if isinstance(package_names, str):
            package_names = [package_names]

        print(f"Installing {', '.join(package_names)} using dnf...")
        try:
            execute(
                self.package_manager["install", "-y", package_names],
                as_sudo=True,
                log=True,
            )
        except CommandNotFound:
            print(
                "dnf command not found. Are you sure you're on a compatible platform?"
            )

    def update(self) -> None:
        print("Updating package list with dnf...")
        execute(self.package_manager["makecache"], as_sudo=True, log=True)

    def __repr__(self):
        return "DNF Package manager"

    def install_kea(self) -> None:
        self.install(["kea", "kea-doc"])

    def search(self, package_name) -> str:
        result = execute(self.package_manager["list", package_name], log=True)
        return result.stdout

    def is_installed(self, package_name) -> bool:
        result = execute(
            self.package_manager["list", "installed", package_name],
            log=True,
            retcodes=(0, 1),
        )
        stdout = result.stdout
        return (
            result.retcode == 0
            and result.stderr is None
            and stdout is not None
            and package_name in stdout
        )


def get_os_release() -> dict[str, str]:
    os_release_info = {}

    if platform.system() != "Linux":
        raise UnsupportedPlatformError(
            f"This script only supports Linux platforms. Got: {platform.uname()}"
        )

    with open("/etc/os-release") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            key, value = line.rstrip().split("=", 1)
            os_release_info[key] = value.strip('"')
    return os_release_info


def get_package_manager() -> PackageManager:
    """
    Return the appropriate package manager class for the current operating system.
    All `PackageManager` subclasses implement a common set of utility functions.

    Returns: a `PackageManager` subclass.
    """
    os_release_info = get_os_release()
    release = os_release_info.get("ID")
    if release in ["ubuntu", "debian", "linuxmint"]:
        return AptPackageManager()
    elif release in ["fedora", "centos", "rhel"]:
        return DnfPackageManager()
    elif release in ["arch", "arch_craft"]:
        raise UnsupportedPlatformError(
            f"Unsupported distribution: you're running Arch ({release}) so you can figure it out ^^"
        )
    else:
        raise UnsupportedPlatformError(f"Unsupported distribution: {release}")


def main():
    try:
        pm = get_package_manager()
        print(pm)
        pm.update()
        print(pm.is_installed("lolcat"))
    except UnsupportedPlatformError as e:
        print(e)
