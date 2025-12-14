"""Unit tests for symbols plugin data models."""

import json

from plugins.plugins.symbols import FieldKindType, UserTypeKindType, WinStructFieldNode, WinStructNode


class TestWinStructNode:
    """Tests for WinStructNode class."""

    def test_struct_kind_detection(self):
        """Should detect struct kind from data."""
        data = {"kind": "struct", "size": 64, "fields": {}}
        node = WinStructNode(name="TestStruct", struct_data=data)

        assert node.kind == UserTypeKindType.Struct
        assert node.size == 64

    def test_union_kind_detection(self):
        """Should detect union kind from data."""
        data = {"kind": "union", "size": 32, "fields": {}}
        node = WinStructNode(name="TestUnion", struct_data=data)

        assert node.kind == UserTypeKindType.Union
        assert node.size == 32

    def test_enum_detection_by_constants(self):
        """Should detect enum when constants field present."""
        data = {"size": 4, "constants": {"A": 0, "B": 1}}
        node = WinStructNode(name="TestEnum", struct_data=data)

        assert node.kind == UserTypeKindType.Enum
        assert node.size == 4

    def test_iter_struct_fields(self):
        """Should iterate over struct fields."""
        data = {
            "kind": "struct",
            "size": 16,
            "fields": {
                "field1": {"offset": 0, "type": {"kind": "base", "name": "int"}},
                "field2": {"offset": 8, "type": {"kind": "base", "name": "long"}},
            },
        }
        node = WinStructNode(name="Test", struct_data=data)

        fields = list(node.iter_child_nodes())

        assert len(fields) == 2
        assert all(isinstance(f, WinStructFieldNode) for f in fields)
        field_names = [f.name for f in fields]
        assert "field1" in field_names
        assert "field2" in field_names

    def test_iter_enum_yields_fields_for_constants(self):
        """Should yield WinStructFieldNode for each enum constant."""
        data = {"size": 4, "constants": {"A": 0, "B": 1, "C": 2}}
        node = WinStructNode(name="TestEnum", struct_data=data)

        fields = list(node.iter_child_nodes())

        assert len(fields) == 3
        assert all(isinstance(f, WinStructFieldNode) for f in fields)

    def test_enum_constant_as_offset(self):
        """Enum constants should be stored as field offset."""
        data = {"size": 4, "constants": {"MY_CONSTANT": 42}}
        node = WinStructNode(name="TestEnum", struct_data=data)

        fields = list(node.iter_child_nodes())

        assert len(fields) == 1
        assert fields[0].offset == 42

    def test_empty_struct(self):
        """Should handle struct with no fields."""
        data = {"kind": "struct", "size": 0, "fields": {}}
        node = WinStructNode(name="EmptyStruct", struct_data=data)

        fields = list(node.iter_child_nodes())

        assert len(fields) == 0
        assert node.size == 0


class TestWinStructFieldNode:
    """Tests for WinStructFieldNode class."""

    def test_offset_extraction(self):
        """Should extract offset from field data."""
        field = WinStructFieldNode(
            name="test_field", field_data={"offset": 128, "type": {"kind": "base", "name": "int"}}
        )

        assert field.offset == 128

    def test_data_type_is_json_string(self):
        """Should encode type data as JSON string."""
        type_data = {"kind": "pointer", "subtype": {"kind": "base", "name": "void"}}
        field = WinStructFieldNode(name="ptr_field", field_data={"offset": 0, "type": type_data})

        assert field.data_type == json.dumps(type_data)
        # Verify it's valid JSON
        assert json.loads(field.data_type) == type_data

    def test_complex_type_encoding(self):
        """Should encode complex nested types."""
        type_data = {
            "kind": "array",
            "count": 10,
            "subtype": {"kind": "pointer", "subtype": {"kind": "struct", "name": "_EPROCESS"}},
        }
        field = WinStructFieldNode(name="array_field", field_data={"offset": 64, "type": type_data})

        # Should be able to store any JSON-serializable type
        assert isinstance(field.data_type, str)
        # Verify the encoded data matches
        assert json.loads(field.data_type) == type_data

    def test_field_name_preservation(self):
        """Should preserve field name."""
        field = WinStructFieldNode(
            name="MyFieldName", field_data={"offset": 0, "type": {"kind": "base", "name": "int"}}
        )

        assert field.name == "MyFieldName"


class TestFieldKindType:
    """Tests for FieldKindType enum."""

    def test_all_kinds_defined(self):
        """Should have all expected field kinds."""
        expected = ["Base", "Pointer", "Function", "Enum", "Array", "Struct", "Union", "Bitfield"]

        for kind in expected:
            assert hasattr(FieldKindType, kind)


class TestUserTypeKindType:
    """Tests for UserTypeKindType enum."""

    def test_all_kinds_defined(self):
        """Should have all expected user type kinds."""
        expected = ["Struct", "Union", "Enum"]

        for kind in expected:
            assert hasattr(UserTypeKindType, kind)
