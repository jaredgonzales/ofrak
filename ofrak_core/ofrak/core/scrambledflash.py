from dataclasses import dataclass
from abc import ABC, abstractmethod
from typing import Iterable

from ofrak.core.binary import GenericBinary
from ofrak.resource import Resource
from ofrak_type.range import Range
from ofrak.component.unpacker import Unpacker, UnpackerError
from ofrak.component.packer import Packer, PackerError
from ofrak.service.resource_service_i import ResourceFilter
from ofrak.model.resource_model import ResourceAttributes

#####################
#     RESOURCES     #
#####################
@dataclass
class ScrambledFlashResource(GenericBinary):
    """
    Resource that has encoding to randomize contents
    Generally encoding is XOR
    """

@dataclass
class ScrambledFlashLogicalDataResource(GenericBinary):
    """
    Decoded `ScrambledFlashResource` from encoding
    """

#####################
#    ATTRIBUTES     #
#####################
class FlashEncodingAlgorithm(ABC):
    """
    Abstract implementation for custom encoding/decoding algorithms 
    """
    @abstractmethod
    def encode(self, payload: bytes, key: bytes) -> bytes:
        raise NotImplementedError()

    @abstractmethod
    def decode(self, payload: bytes, key: bytes) -> bytes:
        raise NotImplementedError()

@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class FlashEncodingAttributes(ResourceAttributes):
    """
    Provide parameters for the custom `FlashEncodingAlgorithm` 
    """
    encoding_algo: FlashEncodingAlgorithm
    encoding_key: Iterable[bytes]
    encoding_length: int

@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class ScrambledFlashAttributes(ResourceAttributes):
    """
    Attributes describing how to scramble/unscramble flash data
    Allows for list to support different algorithms and key
    """
    encoding_pattern: Iterable[FlashEncodingAttributes]


#####################
#    UNPACKERS     #
#####################
class ScrambledFlashResourceUnpacker(Unpacker[None]):
    """
    Unpacks a `ScrambledFlashResource` using a custom decoding algorithm
    Needs `ScrambledFlashAttributes` to supply parameters
    """

    targets = (ScrambledFlashResource,)
    children = (ScrambledFlashLogicalDataResource,)

    async def unpack(self, resource: Resource, config=None):
        try:
            scrambled_attr = resource.get_attributes(ScrambledFlashAttributes)
        except NotFoundError:
            raise UnpackerError("Tried unpacking ScrambledFlashResource with ScrambledFlashAttributes")

        data = await resource.get_data()

        decoded_data = _encode_or_decode(data=data, attr=scrambled_attr, is_encoding=False)

        return await resource.create_child(
            tags=(ScrambledFlashLogicalDataResource,),
            data=decoded_data,
            attributes=[scrambled_attr,],
        )


#####################
#      PACKERS     #
#####################
class ScrambledFlashResourcePacker(Packer[None]):
    """
    Overwrite ourselves with the repacked child
    """
    id = b"ScrambledFlashResourcePacker"
    targets = (ScrambledFlashResource,)
    children = (ScrambledFlashResource,)

    async def pack(self, resource: Resource, config=None):
        packed_child = await resource.get_only_child(
            r_filter=ResourceFilter(
                include_self=True,
                tags=[ScrambledFlashResource,],
            )
        )
        if packed_child is not None:
            patch_data = await packed_child.get_data()
            original_size = await resource.get_data_length()
            resource.queue_patch(Range(0,original_size), patch_data)

class ScrambledFlashLogicalDataResourcePacker(Packer[None]):
    """
    Packs a `ScrambledFlashLogicalDataResource` using a custom encoding algorithm
    Needs `ScrambledFlashAttributes` to supply parameters
    """
    id = b"ScrambledFlashLogicalDataResourcePacker"
    targets = (ScrambledFlashLogicalDataResource,)
    children = (ScrambledFlashLogicalDataResource,)

    async def pack(self, resource: Resource, config=None):
        try:
            scrambled_attr = resource.get_attributes(ScrambledFlashAttributes)
        except NotFoundError:
            raise PackerError("Tried packing ScrambledFlashResource with ScrambledFlashAttributes")

        data = await resource.get_data()

        encoded_data = _encode_or_decode(data=data, attr=scrambled_attr, is_encoding=True)


        # Create child under the original to show it packed itself
        parent = await resource.get_parent()
        return await parent.create_child(
            tags=(ScrambledFlashLogicalDataResource,),
            data=encoded_data,
            attributes=[scrambled_attr,],
        )

#####################
#      HELPERS      #
#####################
def _encode_or_decode(data: bytes, attr: ScrambledFlashAttributes, is_encoding: bool):
    """
    The scrambling function is nearly identical both ways
    It relies on `ScrambledFlashAttributes`
    """
    data_len = len(data)

    out_data = b''
    cur_index = 0
    while cur_index < data_len:
        # Loop through every pattern in the data until out of data
        for pattern in attr.encoding_pattern:
            encoding_algo = pattern.encoding_algo()
            pattern_len = pattern.encoding_length
            if pattern_len == 0:
                payload = data[cur_index:]
            else:
                payload = data[cur_index:cur_index+pattern_len]
            key = pattern.encoding_key

            # Choose either encoding or decoding
            if is_encoding:
                out_data += encoding_algo.encode(payload, key)
            else:
                out_data += encoding_algo.decode(payload, key)
            
            if pattern_len == 0:
                cur_index += len(payload)
            cur_index += pattern_len 
    return out_data

