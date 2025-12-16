"""Unit tests for symbols plugin data models."""

import json

from plugins.plugins.symbols import (
    DataTypeNode,
    FieldKindType,
    StructFieldNode,
    StructNode,
    SymbolsMerkleVisitor,
    UserTypeKindType,
)


class TestStructNode:
    """Tests for StructNode class."""

    def test_struct_kind_detection(self):
        """Should detect struct kind from data."""
        data = {"kind": "struct", "size": 64, "fields": {}}
        node = StructNode(name="TestStruct", struct_data=data)

        assert node.kind == UserTypeKindType.Struct
        assert node.size == 64

    def test_union_kind_detection(self):
        """Should detect union kind from data."""
        data = {"kind": "union", "size": 32, "fields": {}}
        node = StructNode(name="TestUnion", struct_data=data)

        assert node.kind == UserTypeKindType.Union
        assert node.size == 32

    def test_enum_detection_by_constants(self):
        """Should detect enum when constants field present."""
        data = {"size": 4, "constants": {"A": 0, "B": 1}}
        node = StructNode(name="TestEnum", struct_data=data)

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
        node = StructNode(name="Test", struct_data=data)

        fields = list(node.iter_child_nodes())

        assert len(fields) == 2
        assert all(isinstance(f, StructFieldNode) for f in fields)
        field_names = [f.name for f in fields]
        assert "field1" in field_names
        assert "field2" in field_names

    def test_iter_enum_yields_fields_for_constants(self):
        """Should yield StructFieldNode for each enum constant."""
        data = {"size": 4, "constants": {"A": 0, "B": 1, "C": 2}}
        node = StructNode(name="TestEnum", struct_data=data)

        fields = list(node.iter_child_nodes())

        assert len(fields) == 3
        assert all(isinstance(f, StructFieldNode) for f in fields)

    def test_enum_constant_as_offset(self):
        """Enum constants should be stored as field offset."""
        data = {"size": 4, "constants": {"MY_CONSTANT": 42}}
        node = StructNode(name="TestEnum", struct_data=data)

        fields = list(node.iter_child_nodes())

        assert len(fields) == 1
        assert fields[0].offset == 42

    def test_empty_struct(self):
        """Should handle struct with no fields."""
        data = {"kind": "struct", "size": 0, "fields": {}}
        node = StructNode(name="EmptyStruct", struct_data=data)

        fields = list(node.iter_child_nodes())

        assert len(fields) == 0
        assert node.size == 0


class TestStructFieldNode:
    """Tests for StructFieldNode class."""

    def test_offset_extraction(self):
        """Should extract offset from field data."""
        field = StructFieldNode(name="test_field", field_data={"offset": 128, "type": {"kind": "base", "name": "int"}})

        assert field.offset == 128

    def test_data_type_is_json_string(self):
        """Should encode type data as JSON string."""
        type_data = {"kind": "pointer", "subtype": {"kind": "base", "name": "void"}}
        field = StructFieldNode(name="ptr_field", field_data={"offset": 0, "type": type_data})

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
        field = StructFieldNode(name="array_field", field_data={"offset": 64, "type": type_data})

        # Should be able to store any JSON-serializable type
        assert isinstance(field.data_type, str)
        # Verify the encoded data matches
        assert json.loads(field.data_type) == type_data

    def test_field_name_preservation(self):
        """Should preserve field name."""
        field = StructFieldNode(name="MyFieldName", field_data={"offset": 0, "type": {"kind": "base", "name": "int"}})

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


class TestDataTypeNode:
    """Tests for DataTypeNode class."""

    def test_base_type_no_children(self):
        """Base types should have no children."""
        type_data = {"kind": "base", "name": "int"}
        node = DataTypeNode(data_type=type_data)

        children = list(node.iter_child_nodes())

        assert len(children) == 0
        assert node.kind == FieldKindType.Base

    def test_pointer_type_has_one_child(self):
        """Pointer types should yield one child (the subtype)."""
        type_data = {"kind": "pointer", "subtype": {"kind": "base", "name": "void"}}
        node = DataTypeNode(data_type=type_data)

        children = list(node.iter_child_nodes())

        assert len(children) == 1
        assert isinstance(children[0], DataTypeNode)
        assert children[0].kind == FieldKindType.Base
        assert node.kind == FieldKindType.Pointer

    def test_array_type_has_one_child(self):
        """Array types should yield one child (the element type)."""
        type_data = {"kind": "array", "count": 10, "subtype": {"kind": "base", "name": "char"}}
        node = DataTypeNode(data_type=type_data)

        children = list(node.iter_child_nodes())

        assert len(children) == 1
        assert isinstance(children[0], DataTypeNode)
        assert children[0].kind == FieldKindType.Base
        assert node.kind == FieldKindType.Array

    def test_struct_type_no_children(self):
        """Struct type references should have no children (just a name reference)."""
        type_data = {"kind": "struct", "name": "_EPROCESS"}
        node = DataTypeNode(data_type=type_data)

        children = list(node.iter_child_nodes())

        assert len(children) == 0
        assert node.kind == FieldKindType.Struct

    def test_nested_pointer_to_array(self):
        """Pointer to array should produce nested children."""
        type_data = {
            "kind": "pointer",
            "subtype": {"kind": "array", "count": 5, "subtype": {"kind": "base", "name": "int"}},
        }
        node = DataTypeNode(data_type=type_data)

        # First level: pointer yields array child
        children_level1 = list(node.iter_child_nodes())
        assert len(children_level1) == 1
        assert children_level1[0].kind == FieldKindType.Array

        # Second level: array yields base child
        children_level2 = list(children_level1[0].iter_child_nodes())
        assert len(children_level2) == 1
        assert children_level2[0].kind == FieldKindType.Base

    def test_nested_pointer_to_pointer_to_struct(self):
        """Deeply nested types should be traversable."""
        type_data = {
            "kind": "pointer",
            "subtype": {"kind": "pointer", "subtype": {"kind": "struct", "name": "_LIST_ENTRY"}},
        }
        node = DataTypeNode(data_type=type_data)

        # Level 1: outer pointer
        children_level1 = list(node.iter_child_nodes())
        assert len(children_level1) == 1
        assert children_level1[0].kind == FieldKindType.Pointer

        # Level 2: inner pointer
        children_level2 = list(children_level1[0].iter_child_nodes())
        assert len(children_level2) == 1
        assert children_level2[0].kind == FieldKindType.Struct

        # Level 3: struct (no more children)
        children_level3 = list(children_level2[0].iter_child_nodes())
        assert len(children_level3) == 0

    def test_union_type_no_children(self):
        """Union type references should have no children."""
        type_data = {"kind": "union", "name": "_LARGE_INTEGER"}
        node = DataTypeNode(data_type=type_data)

        children = list(node.iter_child_nodes())

        assert len(children) == 0
        assert node.kind == FieldKindType.Union

    def test_enum_type_no_children(self):
        """Enum type references should have no children."""
        type_data = {"kind": "enum", "name": "FILE_SHARE_MODE"}
        node = DataTypeNode(data_type=type_data)

        children = list(node.iter_child_nodes())

        assert len(children) == 0
        assert node.kind == FieldKindType.Enum

    def test_bitfield_type_has_child(self):
        """Bitfield types should have one child (the wrapped type)."""
        type_data = {"kind": "bitfield", "bit_length": 1, "bit_position": 0, "type": {"kind": "base", "name": "int"}}
        node = DataTypeNode(data_type=type_data)

        children = list(node.iter_child_nodes())

        # Bitfield wraps another type and DOES iterate it as child
        assert len(children) == 1
        assert children[0].kind == FieldKindType.Base
        assert node.kind == FieldKindType.Bitfield

    def test_function_type_no_children(self):
        """Function types should have no children."""
        type_data = {"kind": "function"}
        node = DataTypeNode(data_type=type_data)

        children = list(node.iter_child_nodes())

        assert len(children) == 0
        assert node.kind == FieldKindType.Function

    def test_data_type_preservation(self):
        """Should preserve original type data."""
        type_data = {"kind": "pointer", "subtype": {"kind": "base", "name": "char"}}
        node = DataTypeNode(data_type=type_data)

        assert node.data_type == type_data


class TestSymbolsMerkleVisitor:
    """Tests for SymbolsMerkleVisitor hash computation."""

    def test_visit_struct_produces_merkle_node(self):
        """Should convert StructNode to StructMerkleNode."""
        struct_data = {
            "kind": "struct",
            "size": 16,
            "fields": {"field1": {"offset": 0, "type": {"kind": "base", "name": "int"}}},
        }
        struct_node = StructNode(name="TestStruct", struct_data=struct_data)

        with SymbolsMerkleVisitor(thread=True) as visitor:
            visitor.run_visit(struct_node)
            results = list(visitor.as_gen())

        # Should produce field node + struct node
        assert len(results) >= 2
        # Last result should be the struct
        merkle_node = results[-1].return_value
        assert merkle_node.label.name == "Tree"  # Structs use Tree label
        assert merkle_node.size == 16
        assert merkle_node.kind.name == "Struct"
        assert len(merkle_node.hash) == 40  # SHA1 hash

    def test_visit_struct_hash_deterministic(self):
        """Same struct should produce same hash."""
        struct_data = {"kind": "struct", "size": 32, "fields": {}}
        struct_node_1 = StructNode(name="Test", struct_data=struct_data)
        struct_node_2 = StructNode(name="Test", struct_data=struct_data)

        with SymbolsMerkleVisitor(thread=True) as visitor:
            visitor.run_visit(struct_node_1)
            results_1 = list(visitor.as_gen())

        with SymbolsMerkleVisitor(thread=True) as visitor:
            visitor.run_visit(struct_node_2)
            results_2 = list(visitor.as_gen())

        hash_1 = results_1[-1].return_value.hash
        hash_2 = results_2[-1].return_value.hash
        assert hash_1 == hash_2

    def test_visit_struct_different_sizes_different_hash(self):
        """Different struct sizes should produce different hashes."""
        struct_data_1 = {"kind": "struct", "size": 16, "fields": {}}
        struct_data_2 = {"kind": "struct", "size": 32, "fields": {}}
        struct_node_1 = StructNode(name="Test", struct_data=struct_data_1)
        struct_node_2 = StructNode(name="Test", struct_data=struct_data_2)

        with SymbolsMerkleVisitor(thread=True) as visitor:
            visitor.run_visit(struct_node_1)
            results_1 = list(visitor.as_gen())

        with SymbolsMerkleVisitor(thread=True) as visitor:
            visitor.run_visit(struct_node_2)
            results_2 = list(visitor.as_gen())

        hash_1 = results_1[-1].return_value.hash
        hash_2 = results_2[-1].return_value.hash
        assert hash_1 != hash_2  # Different sizes produce different hashes

    def test_visit_struct_with_fields_includes_children(self):
        """Struct with fields should include field children in merkle node."""
        struct_data = {
            "kind": "struct",
            "size": 16,
            "fields": {
                "field1": {"offset": 0, "type": {"kind": "base", "name": "int"}},
                "field2": {"offset": 8, "type": {"kind": "base", "name": "long"}},
            },
        }
        struct_node = StructNode(name="TestStruct", struct_data=struct_data)

        with SymbolsMerkleVisitor(thread=True) as visitor:
            visitor.run_visit(struct_node)
            results = list(visitor.as_gen())

        merkle_node = results[-1].return_value
        assert len(merkle_node.children) == 2
        assert "field1" in merkle_node.children
        assert "field2" in merkle_node.children

    def test_visit_enum_detected_correctly(self):
        """Enum should be detected and labeled correctly."""
        enum_data = {"size": 4, "constants": {"A": 0, "B": 1, "C": 2}}
        enum_node = StructNode(name="TestEnum", struct_data=enum_data)

        with SymbolsMerkleVisitor(thread=True) as visitor:
            visitor.run_visit(enum_node)
            results = list(visitor.as_gen())

        merkle_node = results[-1].return_value
        assert merkle_node.kind.name == "Enum"
        assert len(merkle_node.children) == 3  # 3 constants

    def test_visit_union_detected_correctly(self):
        """Union should be detected and labeled correctly."""
        union_data = {
            "kind": "union",
            "size": 8,
            "fields": {
                "AsInt": {"offset": 0, "type": {"kind": "base", "name": "int"}},
                "AsPointer": {"offset": 0, "type": {"kind": "pointer", "subtype": {"kind": "base", "name": "void"}}},
            },
        }
        union_node = StructNode(name="TestUnion", struct_data=union_data)

        with SymbolsMerkleVisitor(thread=True) as visitor:
            visitor.run_visit(union_node)
            results = list(visitor.as_gen())

        merkle_node = results[-1].return_value
        assert merkle_node.kind.name == "Union"

    def test_visit_data_type_base_produces_merkle_node(self):
        """Base type should produce DataTypeMerkleNode."""
        type_data = {"kind": "base", "name": "int"}
        type_node = DataTypeNode(data_type=type_data)

        with SymbolsMerkleVisitor(thread=True) as visitor:
            visitor.run_visit(type_node)
            results = list(visitor.as_gen())

        assert len(results) == 1
        merkle_node = results[0].return_value
        assert merkle_node.label.name == "Blob"  # Data types use Blob label
        assert merkle_node.kind.name == "Base"
        assert len(merkle_node.hash) == 40  # SHA1 hash

    def test_visit_data_type_pointer_has_child(self):
        """Pointer type should have child merkle node."""
        type_data = {"kind": "pointer", "subtype": {"kind": "base", "name": "void"}}
        type_node = DataTypeNode(data_type=type_data)

        with SymbolsMerkleVisitor(thread=True) as visitor:
            visitor.run_visit(type_node)
            results = list(visitor.as_gen())

        # Should produce: base node, then pointer node
        assert len(results) == 2
        pointer_merkle = results[-1].return_value
        assert pointer_merkle.kind.name == "Pointer"
        assert len(pointer_merkle.children) == 1

    def test_visit_data_type_nested_traversal(self):
        """Nested types should produce bottom-up merkle nodes."""
        type_data = {
            "kind": "pointer",
            "subtype": {"kind": "array", "count": 10, "subtype": {"kind": "struct", "name": "_EPROCESS"}},
        }
        type_node = DataTypeNode(data_type=type_data)

        with SymbolsMerkleVisitor(thread=True) as visitor:
            visitor.run_visit(type_node)
            results = list(visitor.as_gen())

        # Should visit: struct, array, pointer (bottom-up)
        assert len(results) == 3
        assert results[0].return_value.kind.name == "Struct"
        assert results[1].return_value.kind.name == "Array"
        assert results[2].return_value.kind.name == "Pointer"

    def test_visit_field_produces_merkle_node(self):
        """Field should produce StructFieldMerkleNode."""
        field_data = {"offset": 64, "type": {"kind": "base", "name": "int"}}
        field_node = StructFieldNode(name="test_field", field_data=field_data)

        with SymbolsMerkleVisitor(thread=True) as visitor:
            visitor.run_visit(field_node)
            results = list(visitor.as_gen())

        # Field visitor doesn't recursively visit data types (commented out)
        assert len(results) == 1
        field_merkle = results[0].return_value
        assert field_merkle.label.name == "Blob"
        assert field_merkle.offset == 64
        assert len(field_merkle.hash) == 40

    def test_visit_field_hash_includes_data_type(self):
        """Field hash should include data type string."""
        field_data_1 = {"offset": 0, "type": {"kind": "base", "name": "int"}}
        field_data_2 = {"offset": 0, "type": {"kind": "base", "name": "long"}}

        field_node_1 = StructFieldNode(name="field", field_data=field_data_1)
        field_node_2 = StructFieldNode(name="field", field_data=field_data_2)

        with SymbolsMerkleVisitor(thread=True) as visitor:
            visitor.run_visit(field_node_1)
            results_1 = list(visitor.as_gen())

        with SymbolsMerkleVisitor(thread=True) as visitor:
            visitor.run_visit(field_node_2)
            results_2 = list(visitor.as_gen())

        hash_1 = results_1[0].return_value.hash
        hash_2 = results_2[0].return_value.hash
        # Different data types should produce different hashes
        assert hash_1 != hash_2

    def test_hash_includes_all_properties(self):
        """Hash should change when any property changes."""
        # Same struct, different sizes
        struct_1 = StructNode(name="Test", struct_data={"kind": "struct", "size": 16, "fields": {}})
        struct_2 = StructNode(name="Test", struct_data={"kind": "struct", "size": 32, "fields": {}})

        with SymbolsMerkleVisitor(thread=True) as visitor:
            visitor.run_visit(struct_1)
            results_1 = list(visitor.as_gen())

        with SymbolsMerkleVisitor(thread=True) as visitor:
            visitor.run_visit(struct_2)
            results_2 = list(visitor.as_gen())

        hash_1 = results_1[-1].return_value.hash
        hash_2 = results_2[-1].return_value.hash
        assert hash_1 != hash_2  # Different sizes should produce different hashes
