# Python extension module using pybind11
add_library(_uml001 MODULE
    uml001_bindings.cpp
)

# Link against pybind11 and the core C++ library
target_link_libraries(_uml001
    PRIVATE
        pybind11::module
        uml001_core
        ${SODIUM_LIBRARY}
)

# Remove "lib" prefix so the module is named "_uml001.so" or "_uml001.pyd"
set_target_properties(_uml001 PROPERTIES
    PREFIX ""
)

# Windows-specific extension
if (WIN32)
    set_target_properties(_uml001 PROPERTIES SUFFIX ".pyd")
endif()

# Output directory for the module
set_target_properties(_uml001 PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/Release
)
