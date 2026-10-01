"""
Model Loader for Model Auditor

Supports:
- PyTorch / TorchScript (.pt, .pth)
- ONNX (.onnx) via onnxruntime
- Robust fallback when format or weights cannot be loaded:
  records 'Assessment unavailable — required model format/access not available'
  without crashing the audit engine.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np
from PIL import Image
import torch
import torchvision.transforms as transforms

from visionguard.core.crypto import sha256_file
from visionguard.core.schemas import AccessLevelEnum


class BaseModelWrapper(ABC):
    """Abstract interface for audited models."""

    @property
    @abstractmethod
    def model_format(self) -> str:
        pass

    @property
    @abstractmethod
    def access_level(self) -> AccessLevelEnum:
        pass

    @property
    @abstractmethod
    def is_loaded(self) -> bool:
        pass

    @property
    @abstractmethod
    def load_error(self) -> str:
        pass

    @abstractmethod
    def predict(self, input_data: Union[torch.Tensor, np.ndarray, Image.Image]) -> np.ndarray:
        """Run forward pass, returning numpy array of outputs."""
        pass


class PyTorchModelWrapper(BaseModelWrapper):
    """Wraps PyTorch / TorchScript modules for white-box & black-box auditing."""

    def __init__(self, model_or_path: Union[torch.nn.Module, str, Path], device: str = "cpu"):
        self.device = torch.device(device)
        self._format = "pytorch"
        self._access_level = AccessLevelEnum.WHITE_BOX
        self._is_loaded = False
        self._load_error = ""
        self._model: Optional[torch.nn.Module] = None
        self._filepath: Optional[Path] = None
        self._transform = transforms.Compose([
            transforms.Resize(256),
            transforms.CenterCrop(224),
            transforms.ToTensor(),
            transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225])
        ])

        if isinstance(model_or_path, torch.nn.Module):
            self._model = model_or_path.to(self.device).eval()
            self._is_loaded = True
        else:
            self._filepath = Path(model_or_path)
            self._load_from_path()

    def _load_from_path(self):
        if not self._filepath or not self._filepath.is_file():
            self._is_loaded = False
            self._access_level = AccessLevelEnum.UNAVAILABLE
            self._load_error = f"Model file not found: {self._filepath}"
            return

        try:
            # Try loading as TorchScript first
            try:
                self._model = torch.jit.load(str(self._filepath), map_location=self.device)
                self._format = "torchscript"
            except Exception:
                # Try loading as PyTorch checkpoint / state_dict
                checkpoint = torch.load(str(self._filepath), map_location=self.device, weights_only=False)
                if isinstance(checkpoint, torch.nn.Module):
                    self._model = checkpoint
                elif isinstance(checkpoint, dict):
                    # Checkpoint contains state_dict; store state_dict for whitebox stats
                    self._state_dict = checkpoint
                    self._is_loaded = True
                    self._format = "pytorch_state_dict"
                    return
                else:
                    self._is_loaded = False
                    self._access_level = AccessLevelEnum.UNAVAILABLE
                    self._load_error = "Unknown PyTorch checkpoint format."
                    return

            self._model.eval()
            self._model.to(self.device)
            self._is_loaded = True
        except Exception as e:
            self._is_loaded = False
            self._access_level = AccessLevelEnum.UNAVAILABLE
            self._load_error = f"Assessment unavailable — required model format/access not available: {str(e)}"

    @property
    def model_format(self) -> str:
        return self._format

    @property
    def access_level(self) -> AccessLevelEnum:
        return self._access_level

    @property
    def is_loaded(self) -> bool:
        return self._is_loaded

    @property
    def load_error(self) -> str:
        return self._load_error

    @property
    def internal_model(self) -> Optional[torch.nn.Module]:
        return self._model

    def predict(self, input_data: Union[torch.Tensor, np.ndarray, Image.Image]) -> np.ndarray:
        if not self._is_loaded or self._model is None:
            raise RuntimeError(f"Cannot predict: {self._load_error}")

        if isinstance(input_data, Image.Image):
            tensor = self._transform(input_data).unsqueeze(0).to(self.device)
        elif isinstance(input_data, np.ndarray):
            if input_data.ndim == 3:
                tensor = torch.from_numpy(input_data).permute(2, 0, 1).float().unsqueeze(0).to(self.device)
            else:
                tensor = torch.from_numpy(input_data).float().to(self.device)
        elif isinstance(input_data, torch.Tensor):
            tensor = input_data.to(self.device)
        else:
            raise TypeError(f"Unsupported input type: {type(input_data)}")

        with torch.no_grad():
            output = self._model(tensor)
            if isinstance(output, torch.Tensor):
                return output.detach().cpu().numpy()
            elif isinstance(output, (tuple, list)):
                return output[0].detach().cpu().numpy()
            return np.array(output)


class ONNXModelWrapper(BaseModelWrapper):
    """Wraps ONNX model for black-box and structural auditing."""

    def __init__(self, model_path: Union[str, Path]):
        self._filepath = Path(model_path)
        self._format = "onnx"
        self._access_level = AccessLevelEnum.BLACK_BOX
        self._is_loaded = False
        self._load_error = ""
        self._session = None

        if not self._filepath.is_file():
            self._is_loaded = False
            self._access_level = AccessLevelEnum.UNAVAILABLE
            self._load_error = f"Assessment unavailable — required model format/access not available: File not found {self._filepath}"
            return

        try:
            import onnxruntime as ort
            self._session = ort.InferenceSession(str(self._filepath), providers=['CPUExecutionProvider'])
            self._input_name = self._session.get_inputs()[0].name
            self._is_loaded = True
            # ONNX graphs can provide some white-box topology
            self._access_level = AccessLevelEnum.WHITE_BOX
        except Exception as e:
            self._is_loaded = False
            self._access_level = AccessLevelEnum.UNAVAILABLE
            self._load_error = f"Assessment unavailable — required model format/access not available: {str(e)}"

    @property
    def model_format(self) -> str:
        return self._format

    @property
    def access_level(self) -> AccessLevelEnum:
        return self._access_level

    @property
    def is_loaded(self) -> bool:
        return self._is_loaded

    @property
    def load_error(self) -> str:
        return self._load_error

    def predict(self, input_data: Union[torch.Tensor, np.ndarray, Image.Image]) -> np.ndarray:
        if not self._is_loaded or self._session is None:
            raise RuntimeError(f"Cannot predict: {self._load_error}")

        if isinstance(input_data, Image.Image):
            resized = input_data.resize((224, 224), Image.Resampling.BILINEAR)
            arr = np.asarray(resized, dtype=np.float32) / 255.0
            # [H, W, C] -> [1, C, H, W]
            arr = np.transpose(arr, (2, 0, 1))[np.newaxis, ...]
        elif isinstance(input_data, np.ndarray):
            arr = input_data.astype(np.float32)
            if arr.ndim == 3:
                arr = arr[np.newaxis, ...]
        elif isinstance(input_data, torch.Tensor):
            arr = input_data.detach().cpu().numpy().astype(np.float32)
        else:
            raise TypeError(f"Unsupported input type: {type(input_data)}")

        inputs = {self._input_name: arr}
        outputs = self._session.run(None, inputs)
        return outputs[0]


def load_model(model_or_path: Union[torch.nn.Module, str, Path], device: str = "cpu") -> BaseModelWrapper:
    """Universal model loader factory with graceful error handling."""
    if isinstance(model_or_path, torch.nn.Module):
        return PyTorchModelWrapper(model_or_path, device=device)

    path = Path(model_or_path)
    suffix = path.suffix.lower()

    if suffix == ".onnx":
        return ONNXModelWrapper(path)
    elif suffix in (".pt", ".pth", ".bin"):
        return PyTorchModelWrapper(path, device=device)
    else:
        # Try PyTorch loader as fallback
        wrapper = PyTorchModelWrapper(path, device=device)
        if not wrapper.is_loaded:
            wrapper._access_level = AccessLevelEnum.UNAVAILABLE
            wrapper._load_error = f"Assessment unavailable — required model format/access not available (Unsupported extension: {suffix})"
        return wrapper
