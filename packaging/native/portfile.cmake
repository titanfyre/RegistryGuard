vcpkg_download_distfile(ARCHIVE
    URLS "https://github.com/titanfyre/RegistryGuard/releases/download/sdk-v0.1.1/registryguard-sdk-0.1.1.tar.gz"
    FILENAME "registryguard-sdk-0.1.1.tar.gz"
    SHA512 5d1cd2f82a16ea0a3f5cbd379c86b39cf3f2da4513e3f8e0b39afebfa0c1cce224de7cdb12e44150f9b284fb7704fd2b03ab8c4d2eacdf7c1b30ebe177f65412
)
vcpkg_extract_source_archive(SOURCE_PATH ARCHIVE "${ARCHIVE}" NO_REMOVE_ONE_LEVEL)
vcpkg_cmake_configure(SOURCE_PATH "${SOURCE_PATH}")
vcpkg_cmake_install()
vcpkg_cmake_config_fixup(PACKAGE_NAME RegistryGuardSDK CONFIG_PATH lib/cmake/RegistryGuardSDK)
file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include" "${CURRENT_PACKAGES_DIR}/debug/share")
vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/LICENSE")
