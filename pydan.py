from typing import List, Optional, Any, Union
from pydantic import BaseModel, Field
import json
from collections import OrderedDict


class ArgumentItem(BaseModel):
    name: Optional[str]
    description: Optional[str]


class Arguments(BaseModel):
    argument: List[ArgumentItem] | ArgumentItem


class FunctionItem(BaseModel):
    name: str
    dll: Optional[str]
    description: Optional[str]
    args: Arguments | str = Field(alias="arguments")
    returns: Optional[str]

    @property
    def arguments(self) -> List[ArgumentItem]:
        _args = self.args
        if isinstance(_args, str):
            return []
        elif isinstance(_args.argument, ArgumentItem):
            return [_args.argument]
        elif isinstance(_args.argument, list):
            return _args.argument
        else:
            raise TypeError("Invalid argument type")


class Functions(BaseModel):
    function: List[FunctionItem]


class MSDN(BaseModel):
    functions: Functions


with open("r2msdn.json", "r") as f:
    data = json.loads(f.read())

data = MSDN.model_validate(data)

hold: OrderedDict[Union[str, None], Any] = OrderedDict()

for func in data.functions.function:
    args = func.arguments
    if func.dll in hold:
        hold[func.dll].append(func.dict())
    else:
        hold[func.dll] = [func.dict()]

with open("remodelled.json", "w") as f:
    f.write(json.dumps(hold))
