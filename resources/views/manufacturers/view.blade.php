@extends('layouts/default')

{{-- Page title --}}
@section('title')

 {{ $manufacturer->name }}
 {{ trans('general.manufacturer') }}
@parent
@stop

@section('header_right')
    <i class="fa-regular fa-2x fa-square-caret-right pull-right" id="expand-info-panel-button" data-tooltip="true" title="{{ trans('button.show_hide_info') }}"></i>
@endsection

{{-- Page content --}}
@section('content')
    <x-container columns="2">
        <x-page-column class="col-md-9 main-panel">
            <x-tabs>
                <x-slot:tabnav>
                    @can('view', \App\Models\Asset::class)
                        <x-tabs.nav-item
                                name="assets"
                                class="active"
                                icon="fas fa-barcode fa-fw"
                                label="{{ trans('general.assets') }}"
                                count="{{ $manufacturer->assets()->AssetsForShow()->count() }}"
                                tooltip="{{ trans('general.assets') }}"
                        />
                    @endcan

                    @can('view', \App\Models\License::class)
                        <x-tabs.nav-item
                                name="licenses"
                                icon="far fa-save"
                                label="{{ trans('general.licenses') }}"
                                count="{{ $manufacturer->licenses->count() }}"
                                tooltip="{{ trans('general.licenses') }}"
                        />
                    @endcan

                    @can('view', \App\Models\Accessory::class)
                        <x-tabs.nav-item
                                name="accessories"
                                icon="far fa-keyboard fa-fw"
                                label="{{ trans('general.accessories') }}"
                                count="{{ $manufacturer->accessories->count() }}"
                                tooltip="{{ trans('general.accessories') }}"
                        />
                    @endcan

                    @can('view', \App\Models\Consumable::class)
                        <x-tabs.nav-item
                                name="consumables"
                                icon="fas fa-tint fa-fw"
                                label="{{ trans('general.consumables') }}"
                                count="{{ $manufacturer->consumables->count() }}"
                                tooltip="{{ trans('general.consumables') }}"
                        />
                    @endcan

                    @can('view', \App\Models\Component::class)
                        <x-tabs.nav-item
                                name="components"
                                icon="fas fa-hdd fa-fw"
                                label="{{ trans('general.components') }}"
                                count="{{ $manufacturer->components->count() }}"
                                tooltip="{{ trans('general.components') }}"
                        />
                    @endcan

                    @can('update', $manufacturer)
                        <x-tabs.nav-item-upload />
                    @endcan

                </x-slot:tabnav>

                <x-slot:tabpanes>
                    <!-- start assets tab pane -->
                    @can('view', \App\Models\Asset::class)
                        <x-tabs.pane name="assets" class="in active">
                            <x-slot:header>
                                {{ trans('general.assets') }}
                            </x-slot:header>

                            <x-slot:bulkactions>
                                <x-table.bulk-assets />
                            </x-slot:bulkactions>

                            <x-slot:content>
                                <x-table
                                        show_column_search="true"
                                        show_advanced_search="true"
                                        buttons="assetButtons"
                                        api_url="{{ route('api.assets.index', ['manufacturer_id' => $manufacturer->id, 'itemtype' => 'assets']) }}"
                                        :presenter="\App\Presenters\AssetPresenter::dataTableLayout()"
                                        export_filename="export-{{ str_slug($manufacturer->name) }}-assets-{{ date('Y-m-d') }}"
                                />
                            </x-slot:content>
                        </x-tabs.pane>
                    @endcan
                    <!-- end assets tab pane -->

                    <!-- start licenses tab pane -->
                    @can('view', \App\Models\License::class)
                        <x-tabs.pane name="licenses">
                            <x-slot:header>
                                {{ trans('general.licenses') }}
                            </x-slot:header>

                            <x-slot:content>
                                <x-table
                                        show_column_search="true"
                                        show_advanced_search="true"
                                        buttons="licenseButtons"
                                        api_url="{{ route('api.licenses.index', ['manufacturer_id' => $manufacturer->id]) }}"
                                        :presenter="\App\Presenters\LicensePresenter::dataTableLayout()"
                                        export_filename="export-{{ str_slug($manufacturer->name) }}-licenses-{{ date('Y-m-d') }}"
                                />
                            </x-slot:content>
                        </x-tabs.pane>
                    @endcan
                    <!-- end licenses tab pane -->

                    <!-- start accessories tab pane -->
                    @can('view', \App\Models\Accessory::class)
                        <x-tabs.pane name="accessories">
                            <x-slot:header>
                                {{ trans('general.accessories') }}
                            </x-slot:header>

                            <x-slot:content>
                                <x-table
                                        show_column_search="true"
                                        show_advanced_search="true"
                                        buttons="accessoryButtons"
                                        api_url="{{ route('api.accessories.index', ['manufacturer_id' => $manufacturer->id]) }}"
                                        :presenter="\App\Presenters\AccessoryPresenter::dataTableLayout()"
                                        export_filename="export-{{ str_slug($manufacturer->name) }}-accessories-{{ date('Y-m-d') }}"
                                />
                            </x-slot:content>
                        </x-tabs.pane>
                    @endcan
                    <!-- end accessories tab pane -->

                    <!-- start consumables tab pane -->
                    @can('view', \App\Models\Consumable::class)
                        <x-tabs.pane name="consumables">
                            <x-slot:header>
                                {{ trans('general.consumables') }}
                            </x-slot:header>

                            <x-slot:content>
                                <x-table
                                        show_column_search="true"
                                        show_advanced_search="true"
                                        buttons="consumableButtons"
                                        api_url="{{ route('api.consumables.index', ['manufacturer_id' => $manufacturer->id]) }}"
                                        :presenter="\App\Presenters\ConsumablePresenter::dataTableLayout()"
                                        export_filename="export-{{ str_slug($manufacturer->name) }}-consumables-{{ date('Y-m-d') }}"
                                />
                            </x-slot:content>
                        </x-tabs.pane>
                    @endcan
                    <!-- end consumables tab pane -->

                    <!-- start components tab pane -->
                    @can('view', \App\Models\Component::class)
                        <x-tabs.pane name="components">
                            <x-slot:header>
                                {{ trans('general.components') }}
                            </x-slot:header>

                            <x-slot:content>
                                <x-table
                                        show_column_search="true"
                                        show_advanced_search="true"
                                        buttons="componentButtons"
                                        api_url="{{ route('api.components.index', ['manufacturer_id' => $manufacturer->id]) }}"
                                        :presenter="\App\Presenters\ComponentPresenter::dataTableLayout()"
                                        export_filename="export-{{ str_slug($manufacturer->name) }}-components-{{ date('Y-m-d') }}"
                                />
                            </x-slot:content>
                        </x-tabs.pane>
                    @endcan
                    <!-- end components tab pane -->

                </x-slot:tabpanes>
            </x-tabs>
        </x-page-column>
        <x-page-column class="col-md-3">

            <x-box>
                <x-box.info-panel :infoPanelObj="$manufacturer" img_path="{{ app('manufacturers_upload_url') }}">

                    <x-slot:before_list>

                        @can('update', \App\Models\Manufacturer::class)
                            <a href="{{ ($manufacturer->deleted_at=='') ? route('manufacturers.edit', $manufacturer->id) : '#' }}" class="btn btn-block btn-sm btn-warning btn-social hidden-print{{ ($manufacturer->deleted_at!='') ? ' disabled' : '' }}">
                                <x-icon type="edit" />
                                {{ trans('general.update') }}
                            </a>
                        @endcan

                            @can('delete', \App\Models\Manufacturer::class)

                                @if ($manufacturer->assets()->count() > 0)
                                    <button class="btn btn-block btn-sm btn-danger btn-social hidden-print disabled" data-tooltip="true"  data-placement="top" data-title="{{ trans('general.cannot_be_deleted') }}">
                                        <x-icon type="delete" />
                                        {{ trans('general.delete') }}
                                    </button>
                                @else
                                    <button class="btn btn-block btn-sm btn-danger btn-social delete-asset" data-toggle="modal" title="{{ trans('general.delete_what', ['item'=> trans('general.manufacturer')]) }}" data-content="{{ trans('general.sure_to_delete_var', ['item' => $manufacturer->name]) }}" data-target="#dataConfirmModal" data-tooltip="true" data-icon="fa fa-trash" data-placement="top" data-title="{{ trans('general.delete_what', ['item'=> trans('general.manufacturer')]) }}" onClick="return false;">
                                        <x-icon type="delete" />
                                        {{ trans('general.delete') }}
                                    </button>
                                @endif
                            @endcan

                    </x-slot:before_list>

                </x-box.info-panel>
            </x-box>
        </x-page-column>
    </x-container>

@stop

@section('moar_scripts')
@include ('partials.bootstrap-table', ['exportFile' => 'manufacturer' . $manufacturer->name . '-export', 'search' => false])

@stop
